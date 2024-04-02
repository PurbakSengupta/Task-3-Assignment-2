#Server Part
import socket
import ssl

# Load the server's certificate and private key
server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
server_context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')

# Load the client's certificate for authentication
server_context.load_verify_locations('client_cert.pem')

# Create a socket and bind it to a specific address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server is listening on port 12345")

while True:
    # Accept a connection
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Wrap the client socket with SSL and authenticate the client
    ssl_client_socket = server_context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=False)
    try:
        ssl_client_socket.do_handshake()
    except ssl.SSLError as e:
        print(f"Authentication failed: {e}")
        continue

    # Receive the destination address and port
    dest_addr, dest_port = ssl_client_socket.recv(1024).decode().split(':')
    dest_port = int(dest_port)

    # Connect to the destination server
    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_socket.connect((dest_addr, dest_port))

    # Forward traffic between the client and the destination server
    while True:
        data = ssl_client_socket.recv(4096)
        if not data:
            break
        dest_socket.sendall(data)

        response = dest_socket.recv(4096)
        if not response:
            break
        ssl_client_socket.sendall(response)

    print("Connection closed")
#Client Part
import socket
import ssl

# Load the client's certificate and private key
client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
client_context.load_cert_chain(certfile='client_cert.pem', keyfile='client_key.pem')

# Load the server's certificate for server authentication
client_context.load_verify_locations('server_cert.pem')

# Create a socket and connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_client_socket = client_context.wrap_socket(client_socket)
ssl_client_socket.connect(('localhost', 12345))

try:
    # Send the destination address and port
    dest_addr = 'example.com'
    dest_port = 80
    ssl_client_socket.sendall(f"{dest_addr}:{dest_port}".encode())

    # Forward traffic between the client and the destination server
    while True:
        data = ssl_client_socket.recv(4096)
        if not data:
            break
        print(data.decode())


finally:
    # Clean up the connection
    ssl_client_socket.shutdown(socket.SHUT_RDWR)
    ssl_client_socket.close()
