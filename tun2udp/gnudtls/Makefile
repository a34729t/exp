CC = gcc -Wall
LDFLAGS = -L /usr/local/gnutls-3.1.6
CPPFLAGS = -I /usr/local/gnutls-3.1.6/lib
TLS_LIBS = /usr/local/gnutls-3.1.6/lib/.libs/libgnutls.a -lgnutls -lgcrypt -ltasn1 -lz
NETTLE_LIBS = -lhogweed -lnettle -lgmp
LIBS = -lpthread -liconv


all: clean client_echo server_echo dtls_echo dtls_echo_thread

# Basic, slightly modified DTLS client + server (not actually echo)
client_echo: client_echo.c udp.c
	$(CC) -o client_echo client_echo.c udp.c $(TLS_LIBS) $(NETTLE_LIBS) $(LIBS)

server_echo: server_echo.c
	$(CC) -o server_echo server_echo.c $(TLS_LIBS) $(NETTLE_LIBS) $(LIBS)

# Echo server version of the above in one file
dtls_echo: dtls_echo.c udp.c
	$(CC) -o dtls_echo dtls_echo.c udp.c $(TLS_LIBS) $(NETTLE_LIBS) $(LIBS)

# Echo server with some cleanup and threads
dtls_echo_thread: dtls_echo_thread.c udp.c dtls_helper.c
	rm -f dtls_echo_thread
	$(CC) -o dtls_echo_thread dtls_echo_thread.c udp.c dtls_helper.c $(TLS_LIBS) $(NETTLE_LIBS) $(LIBS)

clean:
	rm -f client_echo server_echo dtls_echo dtls_echo_thread
