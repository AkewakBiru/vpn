import socket
import ssl
import getpass

# the host and port the server is using for the ssl socket creation
HOST = "10.37.35.118"
PORT = 60000

sslSettings = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sslSettings.verify_mode = ssl.CERT_REQUIRED

sslSettings.load_verify_locations("./certs/output.pem")

try:
    sslSettings.load_cert_chain(certfile="./certs/Server.crt",
                            keyfile="./certs/private.key", password=getpass.getpass('Password: '))
except OSError:
    print("OS error")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# wraps the socket created into an ssl socket and specifies the side (server_side=True)
sslSocket = sslSettings.wrap_socket(server, server_side=True)
server.close()

if __name__ == "__main__":
    sslSocket.bind((HOST, PORT))
    # listens to port 60000 for any connections after the ssl handshake with the client is done.
    sslSocket.listen(1)
    while True:
        connection, client_addr = sslSocket.accept()
        while True:
            # receive data from the connection created
            data = connection.recv(1024)
            if not data:
                break
            print(f"Received : {data.decode('utf-8')}")
