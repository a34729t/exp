CC = gcc -Wall
LDFLAGS = -L /usr/local/openssl-1.0.1c
CPPFLAGS = -I /usr/local/opt/openssl/include
SSL_LIBS = -lssl -lcrypto -ldl
LIBS = -lpthread


all: tun2udp tun2udp_multinode tun2udp_dtls

tun2udp: tun2udp.c *.h
	cc -o tun2udp tun2udp.c

tun2udp_multinode: tun2udp_multinode.c *.h
	cc -o tun2udp_multinode tun2udp_multinode.c

tun2udp_dtls: tun2udp_dtls.c ssl_helper.c *.h
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o tun2udp_dtls tun2udp_dtls.c ssl_helper.c $(SSL_LIBS) $(LIBS)

clean:
	rm -f tun2udp tun2udp_multinode tun2udp_dtls
