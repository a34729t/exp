CC = gcc
LDFLAGS = -L/usr/local/opt/openssl/lib -lssl -lcrypto
#CPPFLAGS = -I/usr/local/opt/openssl/include

all: clean client server

client: client.c
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o client client.c

server: server.c
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server server.c

clean:
	rm -f client server
