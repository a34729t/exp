CC = gcc -Wall
LDFLAGS = -L /usr/local/openssl-1.0.1c
CPPFLAGS = -I /usr/local/opt/openssl/include
SSL_LIBS = -lssl -lcrypto -ldl -lpthread

all: clean server

server: server.c
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server server.c $(SSL_LIBS)

clean:
	rm -f server

# 1. Get running on mac
# ----> somehow the patches didn't work!?

# 2. Get running on linux
# ----> cannot even find openssl shit!?
