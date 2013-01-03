CC = gcc
LDFLAGS = -L/usr/local/openssl-1.0.1c/include -lssl -lcrypto
#CPPFLAGS = -I/usr/local/opt/openssl/include

all: clean server

server: server.c
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server server.c

clean:
	rm -f server
