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
#include <pthread.h>

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
static pthread_mutex_t* mutex_buf = NULL; 

// Function prototypes
void Die (char *msg) { fprintf(stderr, "%s\n", msg); exit(1); }
void start_server (int port, char local_address[]);
void start_client (int port, char local_address[], char *msg);
void configure_server_ssl (SSL_CTX *ctx);
int THREAD_setup ();
static unsigned long id_function (void);
static void locking_function (int mode, int n, const char *file, int line); 
void* handle_connection(void *info);
int handle_socket_error();

// SSL callbacks (duh)
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);
int generate_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int cookie_len);



struct pass_info {
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
    } server_addr, client_addr;
    SSL *ssl;
};


int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
    // This function asks if we trust the cerificate. Duh, yes we do.
    return 1;
}

int generate_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length=0, resultlength;

    // The peer data structure can also contain IPv6 stuff
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

    if (buffer == NULL) { printf("Out of memory\n"); return 0; }

    // Here, we only support IPv4 (Segelman's code has a switch here for IPv6)
    memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, 
            sizeof(struct in_addr));

    // Calculate HMAC of buffer using secret!
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
            (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int verify_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, resultlength;

    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
    } peer;

    // If secret hasn't been initialized yet, cookie cannot be valid
    if (!cookie_initialized) { return 0; }

    // Read peer information
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    // Create buffer with peer address info
    length = 0;
    length += sizeof(struct in_addr);
    length += sizeof(in_port_t);
    buffer = (unsigned char *) OPENSSL_malloc(length);

    if (buffer == NULL) { printf("Out of memory\n"); return 0; }

    // Copy peer info to buffer
    memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, 
            sizeof(struct in_addr));

    // Calculate HMAC of buffer using secret
    HMAC(EVP_sha1(), (const void *) cookie_secret, COOKIE_SECRET_LENGTH,
            (const unsigned char *) buffer, length, result, &resultlength);
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
        return 1;

    return 0;
}

int main (int argc, char *argv[]) {
    // SSL init
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings(); // readable error messages
    SSL_library_init();       // initialize library
    
    int port = 4567;
    char addr[64] = "127.0.0.1"; // localhost in IPv6
    
    
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
    return 0;
}

void configure_server_ssl (SSL_CTX *ctx) {
    // Configure the SSL context when operating in server mode
    
    SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL"); // accept all ciphers, not recommended
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    // Load cert and key
    // generating certs: http://devsec.org/info/ssl-cert.html
    if (!SSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem", SSL_FILETYPE_PEM))
        Die("Unable to find certificate!");
    if (!SSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem", SSL_FILETYPE_PEM))
        Die("Unable to find private key!");
    if (!SSL_CTX_check_private_key(ctx))
        Die("Invalid private key!");
    
    // Client must authenticate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
}

void start_server (int port, char local_address[]) {    
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;
    pthread_t tid;
    struct pass_info *info;

    ctx = SSL_CTX_new(DTLSv1_server_method());
    configure_server_ssl(ctx); // helper function

    THREAD_setup();

    int sock;    
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
    } server_addr, client_addr;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        Die("Unable to socket()");
    
    // Populate server sockaddr_in
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.s4.sin_family = AF_INET;
    server_addr.s4.sin_addr.s_addr = ntohl(INADDR_ANY);
    server_addr.s4.sin_port = ntohs(port);
    
    if (bind(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in)) < 1)
        Die("Unable to bind() server socket");
    
    while (1) {
        memset(&client_addr, 0, sizeof(struct sockaddr_storage));

        bio = BIO_new_dgram(sock, BIO_NOCLOSE);
        
        // Set and active new timer
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        while (DTLSv1_listen(ssl, &client_addr) <= 0);

        info = (struct pass_info*) malloc (sizeof(struct pass_info));
        memcpy(&info->server_addr, &server_addr, sizeof(struct sockaddr_storage));
        memcpy(&info->client_addr, &client_addr, sizeof(struct sockaddr_storage));
        info->ssl = ssl;

        // Launch new thread!
        if (pthread_create(&tid, NULL, handle_connection, info) != 0) {
            Die("Pthread create error");
        }
    }
    THREAD_cleanup();
}

void start_client (int port, char local_address[], char *msg) {
    printf("msg=[%s]\n", msg);
}

int THREAD_setup () {
    mutex_buf = (pthread_mutex_t *) malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!mutex_buf) { return 0; }

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&mutex_buf[i], NULL);
    }

    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

static unsigned long id_function (void) {
    return (unsigned long) pthread_self();
}

static void locking_function (int mode, int n, const char *file, int line) {
    if (mode && CRYPTO_LOCK) {
        pthread_mutex_lock(&mutex_buf[n]);
    } else {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

 void* handle_connection(void *info) {
     ssize_t len;
     char buf[BUFFER_SIZE];
     char addrbuf[INET6_ADDRSTRLEN];
     struct pass_info *pinfo = (struct pass_info *) info;
     SSL *ssl = pinfo->ssl;
     int sock, reading = 0, ret;
     const int on = 1, off = 0;
     struct timeval timeout;
     int num_timeouts = 0, max_timeouts = 5;

     OPENSSL_assert(pinfo->client_addr.ss.ss_family == 
             pinfo->server_addr.ss.ss_family);
     if ((sock = socket(pinfo->client_addr.ss.ss_family, SOCK_DGRAM, 0)) < 0) {
         printf("Error socket()\n");
         goto cleanup;
     }

#ifdef SO_REUSEPORT
     setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void *) &on, 
             (socklen_t) sizeof(on));
#else
     setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &on,
             (socklen_t) sizeof(on));
#endif

     if (bind(sock, (const struct sockaddr *) &pinfo->server_addr, 
                 sizeof(struct sockaddr_in)) < 0) {
         printf("Error bind()\n");
         goto cleanup;
     }

     // Set new fd (sock) and set BIO to connected
     BIO_set_fd(SSL_get_rbio(ssl), sock, BIO_NOCLOSE);
     BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, 
             &pinfo->client_addr.ss);

     // Finish handshake
     do {
         ret = SSL_accept(ssl);
     } while (ret == 0);

     if (ret < 0) {
         perror("SSL_accept");
         printf("%s\n", ERR_error_string(ERR_get_error(), buf));
         goto cleanup;
     }

     // Set and activate timeouts
     timeout.tv_sec = 5;
     timeout.tv_usec = 0;
     BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

     printf("\nThread %lx: accepted conn from %s:%d\n",
             id_function(),
             inet_ntop(AF_INET, &pinfo->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
             ntohs(pinfo->client_addr.s4.sin_port));

     if (SSL_get_peer_certificate(ssl)) {
         printf("---------------------------------------------------------\n");
         X509_NAME_print_ex_fp(stdout, 
                 X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1, 
                 XN_FLAG_MULTILINE);
         printf("\n\n Cipher: %s", 
                 SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
         printf("----------------------------------------------------------\n");
     }

     // Our socket loop
     while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) && 
             num_timeouts < max_timeouts ) {
         reading = 1;

         // Socket listen (synchronous)
         while (reading) {
             len = SSL_read(ssl, buf, sizeof(buf));

             switch (SSL_get_error(ssl, len)) {
                 case SSL_ERROR_NONE:
                     printf("Thread %lx: read %d bytes\n", id_function(), (int) len);
                     reading = 0;
                     break;
                 case SSL_ERROR_WANT_READ:
                     // Handle socket timeouts
                     if (BIO_ctrl(SSL_get_rbio(ssl), 
                                 BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
                         num_timeouts++;
                         reading = 0;
                     }
                     // Otherwise, try again
                     break;
                 case SSL_ERROR_ZERO_RETURN:
                     reading = 0;
                     break;
                 case SSL_ERROR_SYSCALL:
                     printf("Socket read error: ");
                     if (!handle_socket_error()) goto cleanup;
                     reading = 0;
                     break;
                 case SSL_ERROR_SSL:
                     printf("SSL read error: ");
                     printf("%s (%d)\n", 
                             ERR_error_string(ERR_get_error(), buf),
                             SSL_get_error(ssl, len));
                     goto cleanup;
                     break;
                 default:
                     printf("Unexpected error while reading!\n");
                     goto cleanup;
                     break;
             }
         }

         if (len > 0) {
             len = SSL_write(ssl, buf, len);

             switch (SSL_get_error(ssl, len)) {
                 case SSL_ERROR_NONE:
                     printf("Thread %lx: read %d bytes\n", id_function(), (int) len);
                     break;
                 case SSL_ERROR_WANT_WRITE:
                     // Can't write because of renegotiation so we have to retry
                     // sending the message
                     break;
                 case SSL_ERROR_WANT_READ:
                     // Continue reading
                     break;
                 case SSL_ERROR_SYSCALL:
                     printf("Socket write error: ");
                     if (!handle_socket_error()) goto cleanup;
                     reading = 0;
                     break;
                 case SSL_ERROR_SSL:
                     printf("SSL write error: ");
                     printf("%S (%d)\n",
                             ERR_error_string(ERR_get_error(), buf),
                             SSL_get_error(ssl, len));
                     goto cleanup;
                     break;
                 default:
                     printf("Unexpected error while writing!\n");
                     goto cleanup;
                     break;
             }
         }
     }
     SSL_shutdown(ssl);


cleanup:
     close(sock);
     free(info);
     SSL_free(ssl);
     ERR_remove_state(0);
     printf("Thread %lx: done, connection closed.\n", id_function());
     pthread_exit((void *) NULL);
 }

int handle_socket_error() {
    switch (errno) {
        case EINTR:
            // Interrupted system call
            // Ignore
            printf("Interrupted System call!\n");
            return 1;
        case EBADF:
            // Invalid socket
            // Must close connection
            printf("Invalid socket!\n");
            return 0;
            break;
#ifdef EHOSTDOWN
        case EHOSTDOWN:
            // Host is down
            // Just ignore, might be an attacker sending fake ICMP packets
            printf("Host is down!\n");
            return 1;
#endif
#ifdef ECONNRESET
        case ECONNRESET:
            // Connection reset by peer
            // Jsut ignore, might be an attacker sending fake ICMP packets
            printf("Connection reset by peer!\n");
            return 1;
#endif
        case ENOMEM:
            // Out of memory
            // Must close connection.
            printf("Out of memory!\n");
            return 0;
            break;
        case EACCES:
            // Permission denied
            // Just ignore, we might be blocked by firewall policy
            // Try again and hope for the best
            printf("Permission denied!\n");
            return 1;
            break;
        default:
            // Something unexpected happened
            printf("Unexpected error! (errno = %d)\n", errno);
            return 0;
            break;
    }
    return 0;
}
