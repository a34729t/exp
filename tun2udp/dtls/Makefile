CC = gcc -Wall
SSL_DIR = /Users/nflacco/Projects/exp/tun2udp/dtls/openssl-1.0.1c
LDFLAGS = -L $(SSL_DIR)
CPPFLAGS = -I /Users/nflacco/Projects/exp/tun2udp/dtls/openssl-1.0.1c/include
SSL_LIBS = -lssl -lcrypto -ldl -lpthread

all: clean server

#server2: server2.c
#	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server2 server2.c $(SSL_LIBS)

# server: ./server -L 127.0.0.1 -v -V
# client: ./server -L 127.0.0.1 -v -V -R 127.0.0.1
server: server3_oo.c openssl_utils.h
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server server3_oo.c openssl_utils.c $(SSL_LIBS)

clean:
	rm -f server
