all: tun2udp tun2udp_multinode

tun2udp: tun2udp.c *.h
	cc -o tun2udp tun2udp.c

tun2udp_multinode: tun2udp_multinode.c *.h
	cc -o tun2udp_multinode tun2udp_multinode.c

clean:
	rm -f tun2udp tun2udp_multinode
