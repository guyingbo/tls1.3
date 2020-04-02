from tls.session import TLSClientSession
from tls.connection import ClientConnection


def main():
    psk = bytes.fromhex(
        "b2c9b9f57ef2fbbba8b624070b301d7f278f1b39c352d5fa849f85a3e7a3f77b"
    )
    session = TLSClientSession(
        server_names=["127.0.0.1"], psk=psk, psk_only=True, early_data=b"xyz\n"
    )
    # session = TLSClientSession(server_names=["127.0.0.1"])

    conn = ClientConnection(session)
    conn.connect()
    conn.send(b"haha\n")
    conn.send(b"haha2\n")
    while True:
        data = conn.recv()
        print(data)
        if data == b"bye\n":
            break
    while True:
        try:
            data = input()
        except EOFError:
            break
        conn.send(data.encode() + b"\n")
    conn.close()


main()
