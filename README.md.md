**Network Diagram**

![A picture containing diagram

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.001.png)

The **TUN0** interfaces have been configured in both the **VPN client**  and **VPN server** with an IP address of **192.168.53.99** and **192.168.53.2** respectively.

Assuming host A’s VPN client is mutually authenticated with the VPN server using the TLS protocol:

- A VPN bound packet (a packet that is going to the private network) will go to the **TUN0** interface first and then it is sent to the **eth0** interface. There is an SSL tunnel between **eth0** interface and **ens33** interface of the VPN server. So, any data passed is encrypted (the IP packet shown in table 1 will be encrypted, then encapsulated with **eth0** interface’s IP address as shown in table 2).

**At the TUN0 interface of Host A (VPN client)**

|**Source IP**|**Destination IP**||
| :- | :- | :- |
|**192.168.53.99 (Host A, TUN0)**|**192.168.1.120 (host B, eth0)**|**Data**|
Table 1: IP packet at the TUN0 interface

**At the eth0 interface of Host A**

|**Source IP**|**Destination IP**|**Source IP**|**Destination IP**||
| :- | :- | :- | :- | :- |
|<p>**172.16.186.134**</p><p>**(Host A, eth0)**</p>|<p>**172.16.186.132**</p><p>**(VPN server, ens33)**</p>|<p>**192.168.53.99** </p><p>**(Host A, TUN0)**</p>|<p>**192.168.1.120** </p><p>**(Host B, eth0)**</p>|**Data**|
Table 2: IP packet at the eth0 interface

- Since there is an SSL tunnel created between the VPN client and server, the packet is routed to the **ens33** interface of the VPN server.
- At the VPN server, since the packet is a VPN bound packet, it is given to the **TUN0** interface of the VPN server for decapsulation and decryption.
- After the TUN0 interface finishes the decapsulation and decryption process, it forwards the packet to the **ens37** interface (private network). 
- Finally, it is routed to the destination using the destination IP information in the packet. 

Under normal scenario i.e., without using the VPN tunnel, any host from outside the LAN can’t be connected to hosts inside the private network (LAN). But if the host has a VPN client which is authorized and authenticated (using password) by the VPN server, it can be connected to hosts inside the LAN.

**Connection to the private network without using a VPN client**

![Text

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.002.png)

Figure: ICMP packets from host A to host B (unsuccessful)

Since a Virtual machine is used for this Lab, packet filtering takes place in the host in the private network (think of it as a host-based firewall). So, the firewall rules are:

![Text

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.003.png)

**Connection to the private network using a VPN client**

1. VPN client and VPN server are mutually authenticated using a shared password.

![](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.004.png)

Figure: Authentication password for VPN client

![](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.005.png)

Figure: Authentication password for VPN server

By inputting the correct shared password, the VPN client and server are authenticated, and they create an SSL/TLS socket to encrypt communication.

![Table

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.006.png)

Figure: TLS handshake

1. Connection to the private network after authentication

![Text

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.007.png)

Figure: ICMP packets from host A to host B (successful)

Let’s capture the ICMP packet before it reaches the destination with Wireshark.

**At the TUN0 interface of host A**

![Graphical user interface, application, table, Excel

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.008.png)

Figure: Wireshark packet capture at TUN0 interface of host A







**At the ens33 interface of host A**

![Graphical user interface, application

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.009.png)

Figure: Wireshark packet capture at ens33 interface of host A

**At the ens33 interface of the VPN server**

![Graphical user interface, application, table, Excel

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.010.png)

Figure: Wireshark packet capture at ens33 interface of the VPN server

**At the ens37 interface of the VPN server (gateway for the LAN)**

![Graphical user interface, application, table, Excel

Description automatically generated](Aspose.Words.d0fa60c9-5ead-4786-b7ce-8055a9aec4bd.011.png)

Figure: Wireshark packet capture at ens37 interface of the VPN server


**Client python code**

#!/usr/bin/env python3

import fcntl
import struct
import ssl
import getpass
import os
import time
from scapy.all import \*

TUNSETIFF = 0x400454ca
IFF\_TUN   = 0x0001
IFF\_TAP   = 0x0002
IFF\_NO\_PI = 0x1000

\# Create the tun interface
tun = os.open("/dev/net/tun", os.O\_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF\_TUN | IFF\_NO\_PI)
ifname\_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

\# Get the interface name
ifname = ifname\_bytes.decode('UTF-8')[:16].strip("\x00")

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.1.0/24 dev {}".format(ifname))

SERVER\_IP = "172.16.186.132"
SERVER\_PORT = 9090

sslSettings = ssl.SSLContext(ssl.PROTOCOL\_TLSv1\_2)
sslSettings.verify\_mode = ssl.CERT\_REQUIRED
sslSettings.check\_hostname = True

sslSettings.load\_verify\_locations("./certs2/output.pem")

try:
`    `# getpass is for the password not to be seen when inputted by the user
`    `sslSettings.load\_cert\_chain(certfile="./certs2/client.crt", keyfile="./certs2/clientkey", password=getpass.getpass('Password: '))

except OSError:
`    `print("OS error")

HOST = "172.16.186.134"
PORT = 10000
client = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)

client.setsockopt(socket.SOL\_SOCKET, socket.SO\_REUSEADDR, 1)

sslSocket = sslSettings.wrap\_socket(client, server\_hostname="akewak")
client.close()

sslSocket.bind((HOST, PORT))
sslSocket.connect((SERVER\_IP, SERVER\_PORT))


fds = [sslSocket, tun]
while True:
`        `ready, \_, \_ = select.select(fds, [], [])
`        `for fd in ready:
`                `if fd is sslSocket:
`                        `data = sslSocket.recv(2048)
`                        `pkt = IP(data)
`                        `print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))

`                        `# write to the TUN interface
`                        `os.write(tun, data)
`                `if fd is tun:
`                        `packet = os.read(tun, 2048)
`                        `pkt = IP(packet)
`                        `print("From tun: ==> {} --> {}".format(pkt.src, pkt.dst))
`                        `sslSocket.send(packet)


**Server python code**

#!/usr/bin/env python3
import fcntl
import struct
import ssl
import getpass
import os
from scapy.all import \*


TUNSETIFF = 0x400454ca
IFF\_TUN = 0x0001
IFF\_TAP = 0x0002
IFF\_NO\_PI = 0x1000

\# create the TUN interface

tun = os.open("/dev/net/tun", os.O\_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF\_TUN | IFF\_NO\_PI)
ifname\_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

\# Get the interface name
ifname = ifname\_bytes.decode('UTF-8')[:16].strip("\x00")

os.system("ip addr add 192.168.53.2/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("ip route add 192.168.1.0/24 dev ens37 proto kernel scope link src 192.168.1.1")

\# the host and port the server is using for the ssl socket creation
IP\_A = "0.0.0.0"
PORT = 9090


sslSettings = ssl.SSLContext(ssl.PROTOCOL\_TLSv1\_2)
sslSettings.verify\_mode = ssl.CERT\_REQUIRED

sslSettings.load\_verify\_locations("./certs/output.pem")

try:
`    `sslSettings.load\_cert\_chain(certfile="./certs/Server.crt",
`            `keyfile="./certs/private.key", password=getpass.getpass('Password: '))
except OSError:
`    `print("OS error")


server = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)
server.setsockopt(socket.SOL\_SOCKET, socket.SO\_REUSEADDR, 1)

\# wraps the socket created into an ssl socket and specifies the side (server\_side=True)
sslSocket = sslSettings.wrap\_socket(server, server\_side=True)
server.close()

sslSocket.bind((IP\_A, PORT))

ip = "172.16.186.134"
port = 10000

sslSocket.listen(1)
connection, (ip, port) = sslSocket.accept()

fds = [connection, tun]

while True:
`    `ready, \_, \_ = select.select(fds, [], [])
`    `for fd in ready:

`        `if fd is connection:
`            `print("sock ....")
`            `data = connection.recv(1024)
`            `pkt = IP(data)
`            `print("{}:{} --> {}:{}".format(ip, port, IP\_A, PORT))
`            `print("    Inside tunnel: {} --> {}".format(pkt.src, pkt.dst))

`            `# write to the TUN interface
`            `os.write(tun, data)

`        `if fd is tun:
`            `print("tun ....")
`            `packet = os.read(tun, 2048)
`            `pkt = IP(packet)
`            `print("Return: {} --> {}".format(pkt.src, pkt.dst))
`            `connection.send(packet)

