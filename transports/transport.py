import sys
from abc import ABC, abstractmethod
from enum import IntEnum


class TransportType(IntEnum):
    incoming = 0
    outgoing = 1


class Transport(ABC):

    def __init__(self, transport_type: TransportType):
        self.transport_type = transport_type

    @abstractmethod
    async def read(self, *args, **kwargs):
        sys.exit("not implemented")

    @abstractmethod
    async def write(self, *args, **kwargs):
        sys.exit("not implemented")

    @abstractmethod
    async def upgrade(self, *args, **kwargs):
        sys.exit("not implemented")

    @abstractmethod
    def sync_close(self, *args, **kwargs):
        sys.exit("not implemented")

    @abstractmethod
    async def async_close(self, *args, **kwargs):
        sys.exit("not implemented")

    @abstractmethod
    async def wait_closed(self, *args, **kwargs):
        sys.exit("not implemented")
