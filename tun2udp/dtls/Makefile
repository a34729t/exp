CC = gcc
LDFLAGS = -L /usr/local/openssl-1.0.1c -lssl -lcrypto
CPPFLAGS = -I /usr/local/opt/openssl/include

all: clean server

server: server.c
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o server server.c

clean:
	rm -f server

# 1. Get running on mac
# ----> somehow the patches didn't work!?

# 2. Get running on linux
# ----> cannot even find openssl shit!?
