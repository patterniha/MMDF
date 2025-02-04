import asyncio
import sys
from transports.transport import Transport, TransportType


class TcpStreamTransport(Transport):
    class ErrorData(Exception):
        def __init__(self, data):
            self.data = data

    @classmethod
    async def connect(cls, host, port, **kwargs):
        reader, writer = await asyncio.open_connection(host, port, limit=32767, **kwargs)
        return cls(TransportType.outgoing, reader, writer)

    def __init__(self, transport_type: TransportType, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        if reader._limit != 32767:
            sys.exit("limit must be 32767")
        super().__init__(transport_type)
        self.reader = reader
        self.writer = writer

    async def read(self):
        data = await self.reader.read(n=65536)
        if not data:
            raise self.ErrorData(data)
        if len(data) > 65536:
            sys.exit("impossible to read over 65536")
        return data

    async def write(self, data):
        if not data:
            sys.exit("no data to write")
        self.writer.write(data)
        return await self.writer.drain()

    async def upgrade(self, sslcontext, *,
                      server_hostname,
                      ssl_handshake_timeout,
                      ssl_shutdown_timeout):
        return await self.writer.start_tls(sslcontext, server_hostname=server_hostname,
                                           ssl_handshake_timeout=ssl_handshake_timeout,
                                           ssl_shutdown_timeout=ssl_shutdown_timeout)

    def sync_close(self):
        return self.writer.close()

    async def async_close(self):
        pass

    async def wait_closed(self):
        return await self.writer.wait_closed()
