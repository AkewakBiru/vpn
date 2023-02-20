#!/usr/bin/env python3

import fcntl
import struct
import ssl
import getpass
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
#print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.1.0/24 dev {}".format(ifname))

   # Get a packet from the TUN interface
#packet = os.read(tun, 2048)
#if packet:
#	ip = IP(packet)
#	print(ip.summary())

# send out a packet using the TUN interface from the VPN client
# to the VPN server

SERVER_IP = "172.16.186.132"
SERVER_PORT = 9090

sslSettings = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sslSettings.verify_mode = ssl.CERT_REQUIRED
sslSettings.check_hostname = True

sslSettings.load_verify_locations("./certs2/output.pem")

try:
    # getpass is for the password not to be seen when inputted by the user
    sslSettings.load_cert_chain(certfile="./certs2/client.crt", keyfile="./certs2/clientkey", password=getpass.getpass('Password: '))

except OSError:
    print("OS error")

HOST = "172.16.186.134"
PORT = 10000
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sslSocket = sslSettings.wrap_socket(client, server_hostname="akewak")
client.close()

sslSocket.bind((HOST, PORT))
sslSocket.connect((SERVER_IP, SERVER_PORT))

#connection, (ip, port) = sslSocket.accept()

fds = [sslSocket, tun]
while True:
        ready, _, _ = select.select(fds, [], [])
        for fd in ready:
# 'sock.recvfrom()' returns data received by the sock>
        # created. The return value is 
        # (data, (ip_address, port_number))
        # This is used to decapsulate the packet that has
# been encapsulated and sent by the sender's vpn_client.
# The decapsulated packet inturn has a source and destination
# IP addresses. The 'pkt' variable consists the packet and we
# can extract the source and destination IP addresses from 
# it.
                if fd is sslSocket:
                        #connection, (ip, port) = sslSocket.accept()
                        data = sslSocket.recv(2048)
                        pkt = IP(data)
                        print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))

                        # write to the TUN interface
                        os.write(tun, data)
                if fd is tun:
                        packet = os.read(tun, 2048)
                        pkt = IP(packet)
                        print("From tun: ==> {} --> {}".format(pkt.src, pkt.dst))

                        sslSocket.send(packet)
