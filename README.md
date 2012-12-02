exp
===

learning how to use linux virtual network interfaces


tunproxy.py - http://www.secdev.org/projects/tuntap_udp/files/tunproxy.py
tunclient.c - http://backreference.org/2010/03/26/tuntap-interface-tutorial/


Using simpletun:

server mode
./simpletun -i tun2 -s -d

client mode

./simpletun -i tun2 -d -c 10.0.1.24

Creating and closing tun interfaces with openvpn (use ifconfig to verify)
openvpn --mktun --dev tunX --user nflacco
openvpn --rmtun --dev tunX
