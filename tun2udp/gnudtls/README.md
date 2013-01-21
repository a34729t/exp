#Getting GNUTls with DTLS to work on OSX!

## Intro

You are probably here because you tried screwing around with the OpenSSL DTLS implementation, bravely [patched and documented by Robin Seggelmann](http://sctp.fh-muenster.de/). Then, you tried the examples and after being frustrated by OpenSSL's horrible API and near total lack of documentation, you hoped for something better. The page for [net-snmp.org](http://www.net-snmp.org/wiki/index.php/DTLS_Implementation_Notes) mentions some other options, as does Stackoverflow, most notably GnuTLS. For a non-C programmer working mostly from OSX, getting the GnuTLS examples up and running is a pain in the ass, so I've documented it.

## Note on example code

Most of my code is based of the [GnuTLS DTLS examples](http://www.gnu.org/software/gnutls/manual/html_node/GnuTLS-application-examples.html#GnuTLS-application-examples) and [OpenSSL DTLS examples](http://sctp.fh-muenster.de/dtls-samples.html)

## Project contents

    Makefile            # builds all examples
    README.md           # duh
    certs/
      cert.pem          # server cert
      certreq.csr       # csr
      crl.pem           # random cert that is invalid
      key.pem           # server key
    client_echo.c       # gnutls dtls echo example (corresponds to server_echo.c)
    dtls_echo.c         # gnutls dtls echo example, all in one file
    dtls_echo_thread.c  # gnutls dtls echo example that fires off threads for clients (not working)
    dtls_helper.c       # gnutls dtls helper functions and callbacks
    server_echo.c       # gnutls dtls echo example (corresponds to client_echo.c)
    udp.c               # udp connection helper

## Getting the all the stupid libraries

You need a ton of different stuff. For DTLS support, I used GNUTls 3.1.6, which requires the crypto library Nettle 2.5, plus some other stuff:

*  GNUTLS 3.1.6
*  libnettle 2.5
*  libgrypt (I installed whatever was on homebrew on 1/13/1013)
*  libtasn1 (I installed whatever was on homebrew on 1/13/1013)

Setting things up:

*  Make sure you have some form of gcc- I use [gcc without XCode](https://github.com/kennethreitz/osx-gcc-installer)
*  Follow the instructions [on this page](https://gist.github.com/1753095) but put all the libraries in /usr/local or wherever you like to put libraries
*  Install homebrew if you don't already have it and do `brew install libgcrypt Libtasn1` OR install those libraries manually

I got the following message after `sudo make install` of GNUTls. No idea if it matters!

    configure: WARNING:
    ***
    *** The DNSSEC root key file in /etc/unbound/root.key was not found.
    *** This file is needed for the verification of DNSSEC responses.
    *** Use the command: unbound-anchor -a "/etc/unbound/root.key"
    *** to generate or update it.
    ***

## Building the examples

You cannot simply `gcc -o foo foo.c` the dtls examples. You need to link all the libraries mentioned above:

    gcc -o [name of binary] [name of c source file] [path to libgnutls.a] -lgnutls -lgcrypt -ltasn1 -lz -lhogweed -lnettle -lgmp -lpthread -liconv

You will also need to get the UDP helper functions and certificate verification callback code used in GNUTls examples. The former is in `udp.c` and the latter in `client_echo.c` The included makefile builds everything nicely.

## Running the examples

Using the vanilla examples, you need the certs. After mucking around with certfiles, it turns out you can just use your *.cert as your ca-certfiles.crt, and either have an empty crl.pem, or add a fake invalid cert to it. and bam, it works. For examples with anonymous authentication, see gnutls\_dir/tests/mini\_dtls_heartbeat.c, among others.

To sniff the DTLS packets, use wireshark: `sudo tshark -i lo udp port 5556` (`lo0` on mac usually)

### client\_echo.c and server\_echo.c

Start the server:

    ./server_echo

Start the client:

    $ ./client_echo 
    The certificate is trusted. - Handshake was completed
    - Received 18 bytes: GET / HTTP/1.0

Here's what the server output looks like:

    UDP server ready. Listening to port '5556'.

    Waiting for connection...
    Sending hello verify request to IPv4 127.0.0.1 port 61006
    Waiting for connection...
    Accepted connection from IPv4 127.0.0.1 port 61006
    - Handshake was completed
    received[0001000000000001]: GET / HTTP/1.0


    EOF

    Waiting for connection...

### dtls\_echo.c (send 5 messages back and forth)

I cleaned up the echo client/server, put them in the same file and used Gnu getopt\_long. See the source for details on how to use.

Start the server:

    $ ./dtls_echo -p 5556

Start the client and you'll see it send a few messages back and forth.

    $ ./dtls_echo -c -a 127.0.0.1 -m foo
    Starting in client mode
    The certificate is trusted. - Handshake was completed
    - Received 3 bytes: foo
    - Received 3 bytes: foo
    - Received 3 bytes: foo
    - Received 3 bytes: foo
    - Received 3 bytes: foo

On the server you'll see this output (hopefully):

    Starting in server mode :5556
    UDP server ready. Listening to port '5556'.

    Waiting for connection...
    Sending hello verify request to IPv4 127.0.0.1 port 58861
    Waiting for connection...
    Accepted connection from IPv4 127.0.0.1 port 58861
    - Handshake was completed
    received[0001000000000001]: foo
    received[0001000000000002]: foo
    received[0001000000000003]: foo
    received[0001000000000004]: foo
    received[0001000000000005]: foo
    EOF

    Waiting for connection...

### dtls\_echo_thread.c

This is broken. The client won't run at all, so we use the previous version (dtls\_echo). The threading stuff isn't working right either- the main thread still is communicating with the client socket!

Start the server:

    ./dtls_echo_thread -p 5556
    
Start the client:

    $ ./dtls_echo -c -a 127.0.0.1 -m foo
    Starting in client mode
    The certificate is trusted. - Handshake was completed
    - Received 3 bytes: foo
    - Received 3 bytes: foo
    *** Error: Resource temporarily unavailable, try again.    <------ wtf?

And the server does something strange:

    Starting in server mode :5556
    UDP server ready. Listening to port '5556'.

    Waiting for connection...
    Sending hello verify request to IPv4 127.0.0.1 port 50159
    Waiting for connection...
    Accepted connection from IPv4 127.0.0.1 port 50159
    -> threaded mode
    - Handshake was completed
    Waiting for connection...
    received[0001000000000001]: foo
    received[0001000000000002]: foo
    Sending hello verify request to IPv4 127.0.0.1 port 50159  <------ wtf?
    Waiting for connection...

The `send hello verify request` and `Waiting for connection...` happen in the main thread; the `received[xxx]` is in the client connection thread. WTF?????

## Building off the simple example

* Make it an echo server -- done
* Add multithreading/selector post-handshake (see http://gnutls.org/manual/html_node/Asynchronous-operation.html)
* Combine client + server again?
* Add a timeouts/heartbeat
* Add tun interface
* Load cert/crl/etc from string instead of file

## Todos

* Figure out why DTLS client won't work in threaded code
* Figure out why multithreaded version totally sucks
* Write string2cert functions in `cert_helpers.c`.
http://stackoverflow.com/questions/3614319/practical-nat-traversal-for-reliable-network-connections

## Future useful info

Timers in non-blocking DTLS: http://lists.gnu.org/archive/html/help-gnutls/2012-12/msg00014.html
Known in advance PK auth: http://lists.gnu.org/archive/html/help-gnutls/2012-11/msg00025.html