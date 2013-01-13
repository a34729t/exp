/*
 * Much of the TUN/TAP setup code is based on
 * instructions and code samples at
 * http://backreference.org/2010/03/26/tuntap-interface-tutorial/
 * 
 * The DLTS code is more or less lifted from Robin Seggelman's examples at
 * http://sctp.fh-muenster.de
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
// For some debug functions:
#include <stdio.h>
#include <stdlib.h> // malloc


#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "create_tun_device.h"
#include "ssl_helper.h"

// Function prototypes and macros
void Die (char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }

// Nasty horrible global vars
#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

int verbose = 0;
int veryverbose = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;


int main (int argc, char *argv[]) {
    // Vars
    char devname[128];
	char local_addr[INET6_ADDRSTRLEN+1];
	char remote_addr[INET6_ADDRSTRLEN+1];
    int port = 4567;
    int client = 0;
    int tunflags, tundev;
    // Parse args with getopt like a good boy
    int c;
    while (1) {
        static struct option long_options[] = {
            {"tun-dev",  required_argument, NULL, 't'},
            {"local-address",  required_argument, NULL, 'l'},
            {"remote-address",  required_argument, NULL, 'r'},
            {"port",  required_argument, NULL, 'p'},
            {"client",  no_argument, NULL, 'c'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "t:l:r:p:c", long_options, &option_index);
        
        if (c == -1) break;
        switch (c) {
            case 't':
                strncpy(devname, optarg, sizeof(devname));
                devname[sizeof(devname)-1] = 0;
                break;
            case 'l':
                strncpy(local_addr, optarg, sizeof(local_addr));
                devname[sizeof(local_addr)-1] = 0;
                break;
            case 'r':
                strncpy(remote_addr, optarg, sizeof(remote_addr));
                devname[sizeof(remote_addr)-1] = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'c':
                client = 1;
                break;
            default:
                break;
        }
    }
    
    // Temporary debug printout
    if (client) printf("Initiating tunnel building.\n");
    printf("tun name '%s'\n", devname);
    printf("local %s:%i\n", local_addr, port);
    printf("remote %s:%i\n", remote_addr, port);
        
    tunflags = 0; tunflags |= IFF_TUN; tunflags |= IFF_NO_PI; // tun config    
    tundev = create_tun_device( devname, tunflags );
    if( tundev < 0 ) err( 1, "Failed to create TUN/TAP device" );
    fprintf( stdout, "Created TUN/TAP device '%s'.\n", devname );
    
    /*
        tun2udp creates a udp socket and listens on it and sends from it, no 
        problems, because it doesn't needto wait for any sort of connection
        dtls server uses a server socket and a client socket and puts each 
        client in a new thread (on server side)
    
        to use DTLS, I need to connect from one side so the handshake is 
        initiated and use DTLSv1_server_method and DTLSv1_client_method
    */

    // Always need to do this for OpenSSL
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    /*
       If system is not given a remote address to connect to, it operates in 
       server mode If system is given a remote address, it connects as client
       I will not do this in a multithreaded manner, however, for now at least!
       Then, once that works, try to make the UDP connection a universal module
       (so tcp/tls can be plugged in) 
    */
    
    
    
}


