#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

void Die (char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }
void start_server (int port, char *local_address);
void start_client (int port, char *local_address, char *msg);

static int verbose_flag = 0;

int main (int argc, char *argv[]) {
    // SSL init
    SSL_load_error_strings(); // readable error messages
    SSL_library_init();       // initialize library
    
    int port = 4567;
    char addr[64] = "127.0.0.1";
    
    
    int server_flag = 0;
    char *msg;
    
    // parse command line args
    static struct option long_options[] = {
        {"verbose", no_argument, 0, 'v'},
        {"server", no_argument, 0, 's'},
        {"msg", required_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"addr", required_argument, 0, 'a'},
        {NULL, 0, NULL, 0}
    };
    
    int c;
    int option_index = 0;
    while ((c = getopt_long(argc, argv, "vsm:p:a:",
             long_options, &option_index)) != -1) {
        switch (c) {
        case 'v':
            verbose_flag = 1;
            break;
        case 's':
            server_flag = 1;
            break;
        case 'm':
            msg = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'a':
            strcpy(addr, optarg);
            break;
        default:
            printf ("?? getopt returned character code 0%o ??\n", c);
        }
    }
    
    printf("Using %s:%i\n", addr, port);
    
    if (server_flag) {
        printf("mode=server\n");
        start_server(port, addr);
    } else {
        printf("mode=client\n");
        start_client(port, addr, msg);
    }
}

void start_server (int port, char *local_address) {
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(DTLSv1_server_method());
    
    // Load cert and key
    // generating certs: http://devsec.org/info/ssl-cert.html
    SSL_CTX_use_certificate_chain_file(ctx, "certs/server-cert.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM);
    
    
    
}

void start_client (int port, char *local_address, char *msg) {
    printf("msg=[%s]\n", msg);
}