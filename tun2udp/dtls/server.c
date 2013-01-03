/*
    Copied more or less from Robin Segelmann's code minus IPv6 support:
    http://sctp.fh-muenster.de/dtls/dtls_udp_echo.c
*/

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

#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

static int verbose_flag = 0;
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

// Function prototypes
void Die (char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }
void start_server (int port, char *local_address);
void start_client (int port, char *local_address, char *msg);
void configure_server_ssl (SSL_CTX *ctx);

// SSL callbacks (duh)
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);
int generate_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int cookie_len);

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
    // This function asks if we trust the cerificate. Duh, yes we do.
    return 1;
}

int generate_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length=0, resultlength;
    
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
    } peer;
    
    // Initialize a random secret
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
            printf("Unable to set random cookie secret\n");
            return 0;
        }
        cookie_initialized = 1;
    }
    
    // Read peer information
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
    
    // Create buffer with peer's address and port
    length = 0;
    length += sizeof(struct in_addr);
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);
    return 1;
}

int verify_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
    return 1;
}

int main (int argc, char *argv[]) {
    // SSL init
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings(); // readable error messages
    SSL_library_init();       // initialize library
    
    int port = 4567;
    char addr[64] = "::1"; // localhost in IPv6
    
    
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

void configure_server_ssl (SSL_CTX *ctx) {
    // Configure the SSL context when operating in server mode
    
    SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL"); // accept all ciphers, not recommended
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    // Load cert and key
    // generating certs: http://devsec.org/info/ssl-cert.html
    if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
        Die("Unable to find certificate!");
    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
        Die("Unable to find private key!");
    if (!SSL_CTX_check_private_key(ctx))
        Die("Invalid private key!");
    
    // Client must authenticate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
}

void start_server (int port, char *local_address) {
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(DTLSv1_server_method());
    configure_server_ssl(ctx); // helper function
    
    // TODO verify cert?
    
    int sock;
    struct sockaddr_in server_addr; 
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        Die("Unable to socket()");
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = ntohl(INADDR_ANY);
    server_addr.sin_port = ntohs(port);
    
    if (bind(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in)) < 1)
        Die("Unable to bind() server socket");
    
    while (1) {
        // TODO BIO datagram stuff
    }
    
}

void start_client (int port, char *local_address, char *msg) {
    printf("msg=[%s]\n", msg);
}