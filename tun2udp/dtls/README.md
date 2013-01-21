# Notes on UDP, NAT Traversal and DTLS

## Motivation

My goal is to build a P2P VPN that forwards arbitrary traffic over encrypted UDP tunnels. Current anonymity systems such as TOR and I2P have major limitations- speed, type of traffic they can forward and security. Because of this, private VPNs have become much more popular. Ideally we can take advantage of both systems- provide TOR-like onion routing, but enjoy the speed and traffic-neutrality of a VPN.

[OpenVPN's roadmap page](http://community.openvpn.net/openvpn/wiki/RoadMap) discusses some of the steps they'd like to take in this direction.

## Basic Setup

I'm running a number of Linux VMs (with Ubuntu Server) using Virtual Box in bridged mode. Note that on OSX, you need to have [TUN/TAP for OSX](http://tuntaposx.sourceforge.net/) installed. I have no idea how to set this up on Windows.

## UDP Tunnels

Constructing a bidirectional UDP tunnel is straightforward. The tunnel on each machine consists of a virtual network interface (TUN or TAP) with a UDP client/server forwarding the packets from the virtual network interface to an identical setup on another machine:

`Server 1: [ TUN Interface -> UDP server ] <--> packets on network <--> server 2: [ UDP server | TUN ]`

I found the example code [tun2udp](https://github.com/TOGoS/TUN2UDP) to be very helpful. Here's how you run tun2udp between two VMs:

**VM1**

    sudo ./tun2udp -local-address '10.0.1.24:55511' -remote-address '10.0.1.25:55511' -tun -no-pi -tun-dev tun3 -debug &
    sudo ip link set tun3 up
    sudo ip addr add 10.9.8.1/24 dev tun3

**VM2**

    sudo ./tun2udp -local-address '10.0.1.25:55511' -remote-address '10.0.1.24:55511' -tun -no-pi -tun-dev tun3 -debug &
    sudo ip link set tun3 up
    sudo ip addr add 10.9.8.2/24 dev tun3

With the UDP tunnel up and running you can forward arbitrary traffic over it from either end:

    ping 10.9.8.2 # from VM1
    ssh 10.9.8.1 # from VM2 (at same time)

## Encrypting UDP With DTLS

TCP traffic can be encrypted with TLS/SSL. The equivalent for UDP is DTLS. Unfortunately, it appears the implementations are not great or extremely well documented. The most comprehensive source of info I found was  on [net-snmp.org](http://www.net-snmp.org/wiki/index.php/DTLS_Implementation_Notes).

Cliffs:

* OpenSSL has an implementation, but it has bugs (see [Robin Seggelmann's patches](http://sctp.fh-muenster.de/)), though it is supposedly improving
* There is a GNU implementation with a nice API but it is apparently not very portable
* [Campagnol](http://campagnol.sourceforge.net/) adds some extra classes on top of OpenSSL instead of patching it

I have decided to take the OpenSSL approach as the library is portable, widely used and Robin Seggelmann's examples are pretty thorough and easy to understand.

DTLS has some other benefits:

* It identifies connections from different machines (but not multiple connections from the same machine, which requires a custom application-layer headers
* Via the heartbeat extension, it is easy to see if a connection is still open

### Patching OpenSSL with Robin Seggelman's patches

Download OpenSSL:

    wget ftp://ftp.openssl.org/source/openssl-1.0.1c.tar.gz

Get the patchfile and apply it:

    wget http://sctp.fh-muenster.de/dtls/dtls-bugs-1.0.1.patch
    patch -p0 < dtls-bugs-1.0.1.patch
    
And configure (for OSX use `./Configure darwin64-x86_64-cc`) and make.

### DTLS Echo Client/Server Using Robin Seggelman's Example Code

Get [the DTLS echo client/server code](http://sctp.fh-muenster.de/dtls-samples.html). Note that you'll need to also download OpenSSL and patch it with patches from the same site. I was unable to get the patched code to link in OSX, but it worked fine in Ubuntu.

Compile (keeping in mind the location of your patched OpenSSL):

`gcc -Wall -L /usr/local/openssl-1.0.1c -I /usr/local/opt/openssl/include -o server server2.c -lssl -lcrypto -ldl -lpthread`

Run the server:

`./server -L 127.0.0.1 -v -V`

Run the client:

`./server -L 127.0.0.1 -v -V 127.0.0.1`

Wireshark capture:

`sudo tshark -i lo udp port 23232`

### DTLS Echo Client/Server With Timeouts

Handling timeouts with the above echo server code is trivial.

For the client, we cause a timeout by waiting on the second to last message we sed to the sever. The messagenumber counter decrements, so we do this when it equals 1:

    while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {
        if (messagenumber > 0) {
            if (messagenumber == 1)usleep(1000*1000*6);
            ...
        }
    }

On the server side, we can do whatever we need to in the case `SSL_ERROR_WANT_READ`:

    while (reading) {
        len = SSL_read(ssl, buf, sizeof(buf));
            switch (SSL_get_error(ssl, len)) {
                ...
                case SSL_ERROR_WANT_READ:
                    /* Handle socket timeouts */
                    printf("SSL_ERROR_WANT_READ - handle timeout\n");
                    ...

For write timeouts, we have `SSL_ERROR_WANT_WRITE`.

### DTLS Echo Client/Server With Heartbeat

Only information I have to go on is from [Robin Seggelmann's page](http://sctp.fh-muenster.de/DTLS.pdf) and a line in the echo server code (commented out). When uncommented, this line causes a `SSL_ERROR_WANT_READ` to happen immediately. I have emailed Herr Seggelmann for clarification.

**NO RESPONSE YET**

### DONE...

Add specific message data for client, and then run two clients at once
Sending a heartbeat on read timeout seems to work nicely from server side

### TODO...

1. Figure out how to make security break
2. Make cookie handling not global

### Creating a Connection Object

### Reading Cert from Char*

See [https://gist.github.com/574388](https://gist.github.com/574388).

### UDP Tunnel with DTLS




