// Helper functions lifted directly from DTLS examples at
// http://www.gnu.org/software/gnutls/manual/html_node/GnuTLS-application-examples.html#GnuTLS-application-examples

#ifndef SOCKET_H
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
#endif

#ifndef GNUTLS_H
    #include <gnutls/gnutls.h>
    #include <gnutls/dtls.h>
    #include <getopt.h>
#endif


typedef struct
{
  gnutls_session_t session;
  int fd;
  struct sockaddr *cli_addr;
  socklen_t cli_addr_size;
} priv_data_st;



extern int generate_dh_params (void);
extern gnutls_session_t initialize_tls_session (gnutls_priority_t priority_cache, gnutls_certificate_credentials_t x509_cred);
extern int pull_timeout_func (gnutls_transport_ptr_t ptr, unsigned int ms);
extern ssize_t push_func (gnutls_transport_ptr_t p, const void *data, size_t size);
extern ssize_t pull_func (gnutls_transport_ptr_t p, void *data, size_t size);
extern const char *human_addr (const struct sockaddr *sa, socklen_t salen, char *buf, size_t buflen);
extern int wait_for_connection (int fd);
extern int verify_certificate_callback (gnutls_session_t session);


// function defs

extern int
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


extern int
generate_dh_params (void)
{
  gnutls_dh_params_t dh_params;
  int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LOW);

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, bits);

  return 0;
}

extern gnutls_session_t
initialize_tls_session (gnutls_priority_t priority_cache, gnutls_certificate_credentials_t x509_cred)
{
  gnutls_session_t session;

  gnutls_init (&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);

  gnutls_priority_set (session, priority_cache);

  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

  return session;
}

/* Wait for data to be received within a timeout period in milliseconds
 */
extern int
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

extern ssize_t
push_func (gnutls_transport_ptr_t p, const void *data, size_t size)
{
  priv_data_st *priv = p;

  return sendto (priv->fd, data, size, 0, priv->cli_addr,
                 priv->cli_addr_size);
}

extern ssize_t
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

extern const char *
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