HOW TO RUN THIS SHIZZAAA

VM0(paros):

sudo ./tun2udp -local-address '10.0.1.24:55511' -remote-address '10.0.1.25:55511' -tun -no-pi -tun-dev tun3 -debug
sudo ip link set tun3 up; sudo ip addr add 10.9.8.1/24 dev tun3


VM1(naxos):

sudo ./tun2udp -local-address '10.0.1.25:55511' -remote-address '10.0.1.24:55511' -tun -no-pi -tun-dev tun3 -debug
sudo ip link set tun3 up; sudo ip addr add 10.9.8.2/24 dev tun3

And then you have a magic udp tunnel...


# Remember...

Install latest OpenSSL via http://www.openssl.org/source/
or libssl-dev

Generating certs: http://devsec.org/info/ssl-cert.html