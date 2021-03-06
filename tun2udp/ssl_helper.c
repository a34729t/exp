#include "ssl_helper.h"

void configure_server_ssl (SSL_CTX *ctx, char* certpath, char* keypath) {
    // Configure the SSL context when operating in server mode
    
    SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL"); // accept all ciphers, not recommended
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    
    // Load cert and key
    // generating certs: http://devsec.org/info/ssl-cert.html
    if (!SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM))
        Die("Unable to find certificate!");
    if (!SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM))
        Die("Unable to find private key!");
    if (!SSL_CTX_check_private_key(ctx))
        Die("Invalid private key!");
    
    // Client must authenticate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
}

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
