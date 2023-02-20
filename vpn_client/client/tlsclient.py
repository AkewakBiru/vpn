import pprint
import socket
import ssl
import getpass


sslSettings = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sslSettings.verify_mode = ssl.CERT_REQUIRED
sslSettings.check_hostname = True

sslSettings.load_verify_locations("./certs2/output.pem")

try:
    # getpass is for the password not to be seen when inputted by the user
    sslSettings.load_cert_chain(certfile="./certs2/client.crt", keyfile="./certs2/clientkey", password=getpass.getpass('Password: '))

except OSError:
    print("OS error")

HOST = "127.0.0.1"
PORT = 60000
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sslSocket = sslSettings.wrap_socket(client, server_hostname="akewak")
client.close()

if __name__ == "__main__":
    sslSocket.bind((HOST, PORT))
    sslSocket.connect(("10.37.35.118", 60000))
    cert = sslSocket.getpeercert()
    pprint.pprint(cert)

    for i in range(5):
        from time import sleep

        sslSocket.send("Hello, world".encode("utf-8"))
        sleep(1)





