/* Socket headers */
#ifndef SSL_H
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <sys/types.h>
#endif

/* OpenSSL headers */
#ifndef SSL_H
    #include <openssl/ssl.h>
    #include <openssl/bio.h>
    #include <openssl/err.h>
    #include <openssl/rand.h>
#endif

void configure_server_ssl (SSL_CTX *ctx, char* certpath, char* keypath);
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);
int generate_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie_callback (SSL *ssl, unsigned char *cookie, unsigned int cookie_len);