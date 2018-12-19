import socket
from tls import TLSClientSession


def main():

    quit = False
    sock = None

    def callback(data):
        nonlocal quit, sock
        print(data)
        if data == b"bye\n":
            quit = True

    psk = bytes.fromhex(
        "b2c9b9f57ef2fbbba8b624070b301d7f278f1b39c352d5fa849f85a3e7a3f77b"
    )
    # session = TLSClientSession(
    #     server_names="127.0.0.1", psk=psk, data_callback=callback, psk_only=True, early_data=b"hoho"
    # )
    session = TLSClientSession(server_names="127.0.0.1", data_callback=callback)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 1799))
    sock.sendall(session.pack_client_hello())

    parser = session.parser()
    while not quit:
        server_data = sock.recv(4096)
        parser.send(server_data)
        data = parser.read()
        if data:
            sock.sendall(data)

    sock.sendall(session.pack_close())
    sock.close()

    quit = False
    session = session.resumption(data_callback=callback)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 1799))
    sock.sendall(session.pack_client_hello())

    parser = session.parser()
    while not quit:
        server_data = sock.recv(4096)
        parser.send(server_data)
        data = parser.read()
        if data:
            sock.sendall(data)

    sock.sendall(session.pack_close())
    sock.close()


main()
