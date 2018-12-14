import asyncio
from tls import TLSClient


class TLSClientProtocol(asyncio.Protocol):
    def __init__(self):
        self.reader = asyncio.StreamReader()
        self._client = TLSClient(data_callback=self.reader.feed_data)
        self.parser = self._client.parser()
        self.on_con_lost = asyncio.Future()

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write(self._client.pack_client_hello())

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
        self.transport.write(self._client.pack_application_data(data))

    def close(self):
        self.transport.write(self._client.pack_close())
        self.transport.close()

    async def wait_closed(self):
        return await self.on_con_lost


async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_connection(
        lambda: TLSClientProtocol(), "127.0.0.1", 1799
    )
    for i in range(3):
        data = await protocol.reader.read(65536)
        print(data)
    protocol.close()
    await protocol.wait_closed()


asyncio.run(main())
