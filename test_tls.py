import socket
from tls import TLSClient


def main():
    psk = bytes.fromhex(
        "b2c9b9f57ef2fbbba8b624070b301d7f278f1b39c352d5fa849f85a3e7a3f77b"
    )
    client = TLSClient(psk=psk)
    # client = TLSClient()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 1799))
    sock.sendall(client.pack_client_hello())
    server_data = sock.recv(4096)

    parser = client.parser()
    parser.send(server_data)
    sock.sendall(parser.read())
    sock.sendall(client.pack_application_data(b"ping\n"))
    server_data = sock.recv(4096)
    parser.send(server_data)

    server_data = sock.recv(4096)
    parser.send(server_data)

    for i in range(3):
        server_data = sock.recv(4096)
        parser.send(server_data)
        data = parser.read()
        print(data)

    sock.sendall(client.pack_close())
    sock.close()


main()
