# Simple SSL VPN setup, simulation and packet capture (SEC-335)

**Network Diagram**

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191307-664a7ba2-f558-4dfe-9bf4-7ed7a21afab2.png">

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

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191445-25772a47-efa8-4636-8481-c6b58a62a92a.png">

Figure: ICMP packets from host A to host B (unsuccessful)

Since a Virtual machine is used for this Lab, packet filtering takes place in the host in the private network (think of it as a host-based firewall). So, the firewall rules are:

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191421-778be0c0-b599-440b-aae8-6e44800ad1e1.png">

**Connection to the private network using a VPN client**

1. VPN client and VPN server are mutually authenticated using a shared password.

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191475-98dc5137-68bf-4c8c-a358-52fd2dc773f7.png">

Figure: Authentication password for VPN client

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191493-5392cafd-ef72-462d-91da-953ed83341f4.png">

Figure: Authentication password for VPN server

By inputting the correct shared password, the VPN client and server are authenticated, and they create an SSL/TLS socket to encrypt communication.

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191534-0052df8f-06dd-4378-89fa-0de306396a3e.png">

Figure: TLS handshake

1. Connection to the private network after authentication

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191554-87c38d9c-3976-474c-94c4-94e349bca231.png">

Figure: ICMP packets from host A to host B (successful)

Let’s capture the ICMP packet before it reaches the destination with Wireshark.

**At the TUN0 interface of host A**

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191596-6bbd23fc-a93d-4a90-a7cc-4ead0933ba48.png">

Figure: Wireshark packet capture at TUN0 interface of host A


**At the ens33 interface of host A**

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191637-42f0944e-29bd-4c4c-a8cd-1ab696bcb001.png">

Figure: Wireshark packet capture at ens33 interface of host A

**At the ens33 interface of the VPN server**

<img width="679" alt="image" src="https://user-images.githubusercontent.com/76839589/220191664-f1d837ed-9a1e-4f00-85be-76c88d5c4777.png">

Figure: Wireshark packet capture at ens33 interface of the VPN server

**At the ens37 interface of the VPN server (gateway for the LAN)**

<img width="668" alt="image" src="https://user-images.githubusercontent.com/76839589/220191683-d9addcda-6a99-45c9-8818-4ec26829d6da.png">

Figure: Wireshark packet capture at ens37 interface of the VPN server
