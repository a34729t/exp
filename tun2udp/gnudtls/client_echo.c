/* This example code is placed in the public domain. */
/* Slightly modified version of http://www.gnu.org/software/gnutls/manual/html_node/Simple-Datagram-TLS-client-example.html#Simple-Datagram-TLS-client-example */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#define PEM_CERT_SEP2 "-----BEGIN X509 CERTIFICATE"
#define PEM_CERT_SEP "-----BEGIN CERTIFICATE"

/* A very basic Datagram TLS client, over UDP with X.509 authentication.
 */

#define MAX_BUF 1024
//#define CAFILE "./certs/ca-certificates.crt"
#define CAFILE "./certs/cert.pem"
#define MSG "GET / HTTP/1.0\r\n\r\n"

// sweet sizeofarray macro
#define sizeofarr(x)  (sizeof(x) / sizeof(x[0]))

extern int udp_connect (char *address, char *port);
extern void udp_close (int sd);
extern int verify_certificate_callback (gnutls_session_t session);

int
main (void)
{
  int ret, sd, ii;
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  const char *err;
  gnutls_certificate_credentials_t xcred;

  gnutls_global_init ();

  // trusted x509 auth
  gnutls_certificate_allocate_credentials (&xcred);
  
  /* sets the trusted cas file */
  gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);
  // gnutls_x509_crt_t calist[1];
  // gnutls_x509_crt_t *crt = load_x509_cert_from_file(CAFILE);
  // calist[0] = crt;
  // gnutls_certificate_set_x509_trust (xcred, calist, sizeofarr(calist));
  
  gnutls_certificate_set_verify_function (xcred, verify_certificate_callback);
  
  /* Initialize TLS session */
  gnutls_init (&session, GNUTLS_CLIENT | GNUTLS_DATAGRAM);
  
  /* Use default priorities */
  ret = gnutls_priority_set_direct (session, "NORMAL", &err);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_INVALID_REQUEST)
        {
          fprintf (stderr, "Syntax error at: %s\n", err);
        }
      exit (1);
    }
  
  /* put the x509 credentials to the current session */
  gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_server_name_set (session, GNUTLS_NAME_DNS, "my_host_name", 
                          strlen("my_host_name"));

  /* connect to the peer */
  char *address = "127.0.0.1";
  int port = 5556;
  sd = udp_connect (address, port);

  gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) sd);

  /* set the connection MTU */
  gnutls_dtls_set_mtu (session, 1000);
  gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  /* Perform the TLS handshake */
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

  gnutls_record_send (session, MSG, strlen (MSG));

  ret = gnutls_record_recv (session, buffer, MAX_BUF);
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

  printf ("- Received %d bytes: ", ret);
  for (ii = 0; ii < ret; ii++)
    {
      fputc (buffer[ii], stdout);
    }
  fputs ("\n", stdout);

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