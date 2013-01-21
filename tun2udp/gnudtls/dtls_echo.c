#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <getopt.h>

/* Description:
 * This is the DTLS echo client/server moved into a single program.
 */

// globals
#define PEM_CERT_SEP2 "-----BEGIN X509 CERTIFICATE"
#define PEM_CERT_SEP "-----BEGIN CERTIFICATE"
#define MAX_BUF 1024
#define MAX_MESSAGE_SIZE 1024
// macros
#define sizeofarr (x) (sizeof(x) / sizeof(x[0]))

// prototypes
void dtls_client (char address[], int port, char message[]);
void dtls_server (int port);
void Die (char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }

// for client
int udp_connect (char *address, char *port);
void udp_close (int sd);
int verify_certificate_callback (gnutls_session_t session);

// for server
static int generate_dh_params (void);
static gnutls_session_t initialize_tls_session (void);
static int pull_timeout_func (gnutls_transport_ptr_t ptr, unsigned int ms);
static ssize_t push_func (gnutls_transport_ptr_t p, const void *data,
                          size_t size);
static ssize_t pull_func (gnutls_transport_ptr_t p, void *data, size_t size);
static const char *human_addr (const struct sockaddr *sa, socklen_t salen,
                               char *buf, size_t buflen);
static int wait_for_connection (int fd);

typedef struct
{
  gnutls_session_t session;
  int fd;
  struct sockaddr *cli_addr;
  socklen_t cli_addr_size;
} priv_data_st;





int main(int argc, char **argv)
{
	int port = 5556;
	char address[INET6_ADDRSTRLEN+1];
    int client = 0;
	memset(address, 0, INET6_ADDRSTRLEN+1);
    char message[MAX_MESSAGE_SIZE+1]; // message for client to send
    
    // parse command line args with getopt
    static struct option long_options[] = {
        {"client", no_argument, 0, 'c'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"message", required_argument, 0, 'm'},
        {NULL, 0, NULL, 0}
    };
    
    int c;
    int option_index = 0;
    while ((c = getopt_long(argc, argv, "ca:p:m:",
             long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                client = 1;
                break;
            case 'a':
                client = 1;
                strncpy(address, optarg, INET6_ADDRSTRLEN);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'm':
                strncpy(message, optarg, MAX_MESSAGE_SIZE);
                break;
            default:
                printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }
    
    gnutls_global_init (); // init that shit!
	if (client) {
        printf("Starting in client mode\n");
        dtls_client (address, port, message);
	} else {
	    printf("Starting in server mode %s:%i\n", address, port);
        dtls_server (port);
    }
    
	return 0;
}

void dtls_client (char address[], int port, char message[])
{
    int ret, sd;
    gnutls_session_t session;
    const char *err;
    gnutls_certificate_credentials_t xcred;
    
    // Certs
    char *cafile = "./certs/cert.pem";
    
    // Configure credentials and session
    gnutls_certificate_allocate_credentials (&xcred);
    gnutls_certificate_set_x509_trust_file (xcred, cafile, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_verify_function (xcred, verify_certificate_callback);
    gnutls_init (&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
    
    ret = gnutls_priority_set_direct (session, "NORMAL", &err);
    if (ret < 0) Die (err);
    
    /* put the x509 credentials to the current session */
    gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
    
    // set up connection and properties
    sd = udp_connect (address, port);
    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);
    gnutls_dtls_set_mtu (session, 1000);
    gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    
    // Start TLS handshake
    do
    {
        ret = gnutls_handshake (session);
    }
    while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

    if (ret < 0)
    {
        fprintf (stderr, "*** Handshake failed\n");
        gnutls_perror (ret);
        goto end;
    }
    else
    {
        printf ("- Handshake was completed\n");
    }
    // end of handshake
    
    int j = 5; // send j messages
    do
    {
        // Send and receive message
        gnutls_record_send (session, message, strlen(message));

        ret = gnutls_record_recv (session, message, MAX_MESSAGE_SIZE);
        if (ret == 0)
        {
            printf ("- Peer has closed the TLS connection\n");
            goto end;
        }
        else if (ret < 0)
        {
            fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
            goto end;
        }
        printf ("- Received %d bytes: %s\n", ret, message);
        j--;
    }
    while(j>0);
    
    /* It is suggested not to use GNUTLS_SHUT_RDWR in DTLS
     * connections because the peer's closure message might
     * be lost */
    gnutls_bye (session, GNUTLS_SHUT_WR);
end:
    udp_close (sd);
    gnutls_deinit (session);
    gnutls_certificate_free_credentials (xcred);
    gnutls_global_deinit ();

    return 0;    
}

/* Use global credentials and parameters to simplify
 * the example. */
// TOODO: Make these non-global
static gnutls_certificate_credentials_t x509_cred;
static gnutls_priority_t priority_cache;
static gnutls_dh_params_t dh_params;

void dtls_server (int port)
{
    int listen_sd;
    int sock, ret;
    struct sockaddr_in sa_serv;
    char buffer[MAX_MESSAGE_SIZE];
    int mtu = 1400;
    unsigned char sequence[8];
    gnutls_datum_t cookie_key; // Should this be regenerated for each incoming conn?
    
    // Certs
    char *cafile = "./certs/cert.pem";
    char *crlfile = "./certs/crl.pem";
    char *certfile = "./certs/cert.pem";
    char *keyfile = "./certs/key.pem";
    
    // Configure credentials and session
    gnutls_certificate_allocate_credentials (&x509_cred);
    gnutls_certificate_set_x509_trust_file (x509_cred, cafile, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_crl_file (x509_cred, crlfile, GNUTLS_X509_FMT_PEM);
    ret = gnutls_certificate_set_x509_key_file (x509_cred, certfile, keyfile,
                                          GNUTLS_X509_FMT_PEM);
    if (ret < 0) Die("No keys or certs were found");
    
    // Set some crypto params and other stuff
    generate_dh_params (); // Diffie-Hellman
    gnutls_priority_init (&priority_cache,
            "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE", 
            NULL);
    gnutls_key_generate (&cookie_key, GNUTLS_COOKIE_KEY_SIZE);
    
    /* Socket operations
     */
    listen_sd = socket (AF_INET, SOCK_DGRAM, 0);

    memset (&sa_serv, '\0', sizeof (sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons (port);

/* DTLS requires the IP don't fragment (DF) bit to be set */
#if defined(IP_DONTFRAG)
      int optval = 1;
      setsockopt (listen_sd, IPPROTO_IP, IP_DONTFRAG,
                  (const void *) &optval, sizeof (optval));
#elif defined(IP_MTU_DISCOVER)
      int optval = IP_PMTUDISC_DO;
      setsockopt(listen_sd, IPPROTO_IP, IP_MTU_DISCOVER, 
                 (const void*) &optval, sizeof (optval));
#endif

    bind (listen_sd, (struct sockaddr *) &sa_serv, sizeof (sa_serv));

    printf ("UDP server ready. Listening to port '%d'.\n\n", port);
    
    for (;;)
    {
        printf ("Waiting for connection...\n");

        sock = wait_for_connection (listen_sd);
        if (sock < 0) continue;

        // Someone is accepting a connection, get data structures ready
        priv_data_st priv;
        gnutls_dtls_prestate_st prestate;
        gnutls_session_t session;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_size;

        cli_addr_size = sizeof (cli_addr);
        ret = recvfrom (sock, buffer, sizeof (buffer), MSG_PEEK,
                        (struct sockaddr *) &cli_addr, &cli_addr_size);
        if (ret > 0)
        {
            memset (&prestate, 0, sizeof (prestate));
            ret = gnutls_dtls_cookie_verify (&cookie_key, &cli_addr,
                                             sizeof (cli_addr), buffer, ret,
                                             &prestate);
            if (ret < 0) /* cookie not valid */
            {
                priv_data_st s;

                memset (&s, 0, sizeof (s));
                s.fd = sock;
                s.cli_addr = (void *) &cli_addr;
                s.cli_addr_size = sizeof (cli_addr);

                printf ("Sending hello verify request to %s\n",
                        human_addr ((struct sockaddr *) &cli_addr,
                                    sizeof (cli_addr), buffer,
                                    sizeof (buffer)));

                gnutls_dtls_cookie_send (&cookie_key, &cli_addr,
                                         sizeof (cli_addr), &prestate,
                                         (gnutls_transport_ptr_t) & s,
                                         push_func);

                /* discard peeked data */
                recvfrom (sock, buffer, sizeof (buffer), 0,
                          (struct sockaddr *) &cli_addr, &cli_addr_size);
                usleep (100);
                continue;
              }
            printf ("Accepted connection from %s\n",
                    human_addr ((struct sockaddr *)
                                &cli_addr, sizeof (cli_addr), buffer,
                                sizeof (buffer)));
          }
        else
          continue;

        session = initialize_tls_session ();
        gnutls_dtls_prestate_set (session, &prestate);
        gnutls_dtls_set_mtu (session, mtu);

        priv.session = session;
        priv.fd = sock;
        priv.cli_addr = (struct sockaddr *) &cli_addr;
        priv.cli_addr_size = sizeof (cli_addr);

        gnutls_transport_set_ptr (session, &priv);
        gnutls_transport_set_push_function (session, push_func);
        gnutls_transport_set_pull_function (session, pull_func);
        gnutls_transport_set_pull_timeout_function (session, pull_timeout_func);

        do
          {
            ret = gnutls_handshake (session);
          }
        while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

        if (ret < 0)
          {
            fprintf (stderr, "Error in handshake(): %s\n",
                     gnutls_strerror (ret));
            gnutls_deinit (session);
            continue;
          }

        printf ("- Handshake was completed\n");

        for (;;)
          {
            do
              {
                ret = gnutls_record_recv_seq (session, buffer, MAX_MESSAGE_SIZE,
                                              sequence);
              }
            while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

            if (ret < 0)
              {
                fprintf (stderr, "Error in recv(): %s\n",
                         gnutls_strerror (ret));
                break;
              }
            if (ret == 0)
              {
                printf ("EOF\n\n");
                break;
              }
            buffer[ret] = 0;
            printf ("received[%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x]: %s\n",
                    sequence[0], sequence[1], sequence[2], sequence[3],
                    sequence[4], sequence[5], sequence[6], sequence[7], buffer);

            /* reply back */
            ret = gnutls_record_send (session, buffer, ret);
            if (ret < 0)
              {
                fprintf (stderr, "Error in send(): %s\n",
                         gnutls_strerror (ret));
                break;
              }
          }

        gnutls_bye (session, GNUTLS_SHUT_WR);
        gnutls_deinit (session);

    }
    close (listen_sd);

    gnutls_certificate_free_credentials (x509_cred);
    gnutls_priority_deinit (priority_cache);

    gnutls_global_deinit ();
}


// These helper functions should probably all go in a separate file?


static int
wait_for_connection (int fd)
{
  fd_set rd, wr;
  int n;

  FD_ZERO (&rd);
  FD_ZERO (&wr);

  FD_SET (fd, &rd);

  /* waiting part */
  n = select (fd + 1, &rd, &wr, NULL, NULL);
  if (n == -1 && errno == EINTR)
    return -1;
  if (n < 0)
    {
      perror ("select()");
      exit (1);
    }

  return fd;
}


static int
generate_dh_params (void)
{
  int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW);

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, bits);

  return 0;
}

static gnutls_session_t
initialize_tls_session (void)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);

  gnutls_priority_set (session, priority_cache);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  return session;
}

/* Wait for data to be received within a timeout period in milliseconds
 */
static int
pull_timeout_func (gnutls_transport_ptr_t ptr, unsigned int ms)
{
  fd_set rfds;
  struct timeval tv;
  priv_data_st *priv = ptr;
  struct sockaddr_in cli_addr;
  socklen_t cli_addr_size;
  int ret;
  char c;

  FD_ZERO (&rfds);
  FD_SET (priv->fd, &rfds);

  tv.tv_sec = 0;
  tv.tv_usec = ms * 1000;

  while(tv.tv_usec >= 1000000)
    {
      tv.tv_usec -= 1000000;
      tv.tv_sec++;
    }

  ret = select (priv->fd + 1, &rfds, NULL, NULL, &tv);

  if (ret <= 0)
    return ret;

  /* only report ok if the next message is from the peer we expect
   * from 
   */
  cli_addr_size = sizeof (cli_addr);
  ret =
    recvfrom (priv->fd, &c, 1, MSG_PEEK, (struct sockaddr *) &cli_addr,
              &cli_addr_size);
  if (ret > 0)
    {
      if (cli_addr_size == priv->cli_addr_size
          && memcmp (&cli_addr, priv->cli_addr, sizeof (cli_addr)) == 0)
        return 1;
    }

  return 0;
}

static ssize_t
push_func (gnutls_transport_ptr_t p, const void *data, size_t size)
{
  priv_data_st *priv = p;

  return sendto (priv->fd, data, size, 0, priv->cli_addr,
                 priv->cli_addr_size);
}

static ssize_t
pull_func (gnutls_transport_ptr_t p, void *data, size_t size)
{
  priv_data_st *priv = p;
  struct sockaddr_in cli_addr;
  socklen_t cli_addr_size;
  char buffer[64];
  int ret;

  cli_addr_size = sizeof (cli_addr);
  ret =
    recvfrom (priv->fd, data, size, 0, (struct sockaddr *) &cli_addr,
              &cli_addr_size);
  if (ret == -1)
    return ret;

  if (cli_addr_size == priv->cli_addr_size
      && memcmp (&cli_addr, priv->cli_addr, sizeof (cli_addr)) == 0)
    return ret;

  printf ("Denied connection from %s\n",
          human_addr ((struct sockaddr *)
                      &cli_addr, sizeof (cli_addr), buffer, sizeof (buffer)));

  gnutls_transport_set_errno (priv->session, EAGAIN);
  return -1;
}

static const char *
human_addr (const struct sockaddr *sa, socklen_t salen,
            char *buf, size_t buflen)
{
  const char *save_buf = buf;
  size_t l;

  if (!buf || !buflen)
    return NULL;

  *buf = '\0';

  switch (sa->sa_family)
    {
#if HAVE_IPV6
    case AF_INET6:
      snprintf (buf, buflen, "IPv6 ");
      break;
#endif

    case AF_INET:
      snprintf (buf, buflen, "IPv4 ");
      break;
    }

  l = strlen (buf);
  buf += l;
  buflen -= l;

  if (getnameinfo (sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) != 0)
    return NULL;

  l = strlen (buf);
  buf += l;
  buflen -= l;

  strncat (buf, " port ", buflen);

  l = strlen (buf);
  buf += l;
  buflen -= l;

  if (getnameinfo (sa, salen, NULL, 0, buf, buflen, NI_NUMERICSERV) != 0)
    return NULL;

  return save_buf;
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches, as well as the activation, expiration dates.
 */
extern int
verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  int ret, type;
  const char *hostname;
  gnutls_datum_t out;

  /* read hostname */
  hostname = gnutls_session_get_ptr (session);

  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers3 (session, hostname, &status);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  type = gnutls_certificate_type_get (session);

  ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  
  printf ("%s", out.data);
  
  gnutls_free(out.data);

  if (status != 0) /* Certificate is not trusted */
      return GNUTLS_E_CERTIFICATE_ERROR;

  /* notify gnutls to continue handshake normally */
  return 0;
}