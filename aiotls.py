import asyncio
from tls import TLSClientSession


class TLSClient(asyncio.Protocol):
    def __init__(self):
        self.reader = asyncio.StreamReader()
        self._session = TLSClientSession(data_callback=self.reader.feed_data)
        self.parser = self._session.parser()
        self.on_con_lost = asyncio.Future()

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(self._session.pack_client_hello())
        self.reader.set_transport(transport)

    def data_received(self, data):
        self.parser.send(data)
        to_send = self.parser.read()
        if to_send:
            self.transport.write(to_send)

    def eof_received(self):
        self.reader.feed_eof()
        self.close()

    def connection_lost(self, exc):
        self.transport.close()
        if exc:
            self.on_con_lost.set_exception(exc)
        else:
            self.on_con_lost.set_result(None)

    def write(self, data):
        self.transport.write(self._session.pack_application_data(data))

    def close(self):
        self.transport.write(self._session.pack_close())
        self.transport.close()

    async def wait_closed(self):
        return await self.on_con_lost


async def main():
    loop = asyncio.get_running_loop()
    transport, client = await loop.create_connection(
        lambda: TLSClient(), "127.0.0.1", 1799
    )
    for i in range(3):
        data = await client.reader.read(65536)
        client.write(data)
        print(data)
    client.close()
    await client.wait_closed()


asyncio.run(main())
