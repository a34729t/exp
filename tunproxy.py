#! /usr/bin/env python

#############################################################################
##                                                                         ##
## tunproxy.py --- small demo program for tunneling over UDP with tun/tap  ##
##                                                                         ##
## Copyright (C) 2003  Philippe Biondi <phil@secdev.org>                   ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License as published by the   ##
## Free Software Foundation; either version 2, or (at your option) any     ##
## later version.                                                          ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################


import os, sys
from socket import *
from fcntl import ioctl
from select import select
import getopt, struct

MAGIC_WORD = "Wazaaaaaaaaaaahhhh !"

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002

TUNMODE = IFF_TUN
MODE = 0
DEBUG = 0

def usage(status=0):
    print "Usage: tunproxy [-s port|-c targetip:port] [-e]"
    sys.exit(status)

opts = getopt.getopt(sys.argv[1:],"s:c:ehd")

for opt,optarg in opts[0]:
    if opt == "-h":
        usage()
    elif opt == "-d":
        DEBUG += 1
    elif opt == "-s":
        MODE = 1
        PORT = int(optarg)
    elif opt == "-c":
        MODE = 2
        IP,PORT = optarg.split(":")
        PORT = int(PORT)
        peer = (IP,PORT)
    elif opt == "-e":
        TUNMODE = IFF_TAP
        
if MODE == 0:
    usage(1)


f = os.open("/dev/net/tun", os.O_RDWR)
ifs = ioctl(f, TUNSETIFF, struct.pack("16sH", "toto%d", TUNMODE))
ifname = ifs[:16].strip("\x00")

print "Allocated interface %s. Configure it and use it" % ifname

s = socket(AF_INET, SOCK_DGRAM)

try:
    if MODE == 1:
        s.bind(("", PORT))
        while 1:
            word,peer = s.recvfrom(1500)
            if word == MAGIC_WORD:
                break
            print "Bad magic word for %s:%i" % peer
        s.sendto(MAGIC_WORD, peer)
    else:
        s.sendto(MAGIC_WORD, peer)
        word,peer = s.recvfrom(1500)
        if word != MAGIC_WORD:
            print "Bad magic word for %s:%i" % peer
            sys.exit(2)
    print "Connection with %s:%i established" % peer
    
    while 1:
        r = select([f,s],[],[])[0][0]
        if r == f:
            if DEBUG: os.write(1,">")
            s.sendto(os.read(f,1500),peer)
        else:
            buf,p = s.recvfrom(1500)
            if p != peer:
                print "Got packet from %s:%i instead of %s:%i" % (p+peer)
                continue
            if DEBUG: os.write(1,"<")
            os.write(f, buf)
except KeyboardInterrupt:
    print "Stopped by user."
