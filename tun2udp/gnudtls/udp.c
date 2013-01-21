/* This example code is placed in the public domain. */
// from http://www.gnu.org/software/gnutls/manual/html_node/Helper-functions-for-UDP-connections.html#Helper-functions-for-UDP-connections

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* udp.c */
int udp_connect (char *SERVER, int PORT);
void udp_close (int sd);

/* Connects to the peer and returns a socket
 * descriptor.
 */
extern int
udp_connect (char *SERVER, int PORT)
{
  int err, sd;
  struct sockaddr_in sa;

  /* connects to server
   */
  sd = socket (AF_INET, SOCK_DGRAM, 0);

  memset (&sa, '\0', sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  inet_pton (AF_INET, SERVER, &sa.sin_addr);

#if defined(IP_DONTFRAG)
  optval = 1;
  setsockopt (sd, IPPROTO_IP, IP_DONTFRAG,
              (const void *) &optval, sizeof (optval));
#elif defined(IP_MTU_DISCOVER)
  optval = IP_PMTUDISC_DO;
  setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, 
             (const void*) &optval, sizeof (optval));
#endif

  err = connect (sd, (struct sockaddr *) & sa, sizeof (sa));
  if (err < 0)
    {
      fprintf (stderr, "Connect error\n");
      exit (1);
    }

  return sd;
}

/* closes the given socket descriptor.
 */
extern void
udp_close (int sd)
{
  close (sd);
}