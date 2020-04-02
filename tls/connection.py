import socket
from .session import EventType


class ClientConnection:
    def __init__(self, session):
        self.session = session
        self.sock = None

    def connect(self):
        self.sock = socket.socket()
        self.sock.connect(("127.0.0.1", 1799))
        data = self.session.client_hello()
        self.sock.sendall(data)
        _quit = False
        while not _quit:
            data = self.sock.recv(4096)
            if not data:
                raise Exception("connect failed")
            events = self.session.wait_server_hello(data)
            for event in events:
                if event.event_type == EventType.should_send:
                    self.sock.sendall(event.data)
                elif event.event_type == EventType.should_close:
                    self.sock.close()
                    raise Exception("connect failed")
                elif event.event_type == EventType.received:
                    print(event.data)
                elif event.event_type == EventType.connected:
                    _quit = True
        print("connected")
        data = self.session.client_finish()
        self.sock.sendall(data)
        print("client finished")

    def send(self, data: bytes):
        data = self.session.send(data)
        self.sock.sendall(data)

    def recv(self):
        while True:
            data = self.sock.recv(4096)
            if not data:
                return
            res = self.session.recv(data)
            if res:
                return res

    def close(self):
        data = self.session.close()
        self.sock.sendall(data)
        self.sock.close()
