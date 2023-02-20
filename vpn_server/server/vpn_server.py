#!/usr/bin/env python3
import fcntl
import struct
import ssl
import getpass
import os
from scapy.all import *


TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# create the TUN interface

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'akewak%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

os.system("ip addr add 192.168.53.2/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
#os.system("ip route add 192.168.1.0/24 dev ens37 proto kernel scope link src 192.168.1.1")

#os.system("ip route add 192.168.1.0/24 dev ens37")



# the host and port the server is using for the ssl socket creation
IP_A = "0.0.0.0"
PORT = 9090


sslSettings = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sslSettings.verify_mode = ssl.CERT_REQUIRED

sslSettings.load_verify_locations("./certs/output.pem")

try:
    sslSettings.load_cert_chain(certfile="./certs/Server.crt",
            keyfile="./certs/private.key", password=getpass.getpass('Password: '))
except OSError:
    print("OS error")

# socket to send the packet to the gateway (ens37)
#gatesock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#gatesock.bind(('127.0.0.1', 43000))

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# wraps the socket created into an ssl socket and specifies the side (server_side=True)
sslSocket = sslSettings.wrap_socket(server, server_side=True)
server.close()

#sslSocket.bind(("172.16.186.133", PORT))
sslSocket.bind((IP_A, PORT))

#sslSocket.listen(1)
ip = "172.16.186.134"
port = 10000

sslSocket.listen(1)
connection, (ip, port) = sslSocket.accept()

fds = [connection, tun]

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
# it
        if fd is connection:
            #sslSocket.listen(1)
            print("sock ....")
            #connection, (ip, port) = sslSocket.accept()
            data = connection.recv(1024)
            pkt = IP(data)
            print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
            print("	Inside tunnel: {} --> {}".format(pkt.src, pkt.dst))

			# write to the TUN interface
            os.write(tun, data)
#        if fd is gatesock:
#            print("Sock ....")
#            data, (ip, port) = gatesock.recvfrom(1024)


        if fd is tun:
            print("tun ....")
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("Return: {} --> {}".format(pkt.src, pkt.dst))
            connection.send(packet)

