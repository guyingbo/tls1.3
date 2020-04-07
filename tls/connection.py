import socket


class ClientConnection:
    def __init__(self, session):
        self.session = session
        self.sock = None

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect(("127.0.0.1", 1799))
        self.session._parser.run(self.sock)

    def send(self, data: bytes):
        data = self.session.send(data)
        self.sock.sendall(data)

    def recv(self):
        return self.session._parser.run(self.sock)

    def close(self):
        data = self.session.close()
        self.sock.sendall(data)
        self.sock.close()
