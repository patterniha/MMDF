import sys
import asyncio
import traceback
from abc import abstractmethod, ABC
from transports.wrapped_transport import WrappedTransport


class AbstractTransportManager(ABC):
    class ExitMainLoop(Exception):
        def __init__(self, transport_manager: 'AbstractTransportManager'):
            self.created_task = asyncio.current_task()
            self.transport_manager = transport_manager

    async def main_loop(self, tp: WrappedTransport):
        try:
            if not isinstance(tp, WrappedTransport):
                sys.exit("wrong tp for main_loop")
            if asyncio.current_task() is not tp.created_task:
                sys.exit("read/upgrade out of context")
            await self.main_loop_initialize(tp)
            while True:
                await self.main_loop_read(tp)
        except self.ExitMainLoop as e:
            if asyncio.current_task() is not tp.created_task:
                sys.exit("read/upgrade out of context")
            if (e.created_task is tp.created_task) and (e.transport_manager is self):
                return
            sys.exit("other main loop exit")
        except Exception as e:
            traceback.print_exc()
            sys.exit(repr(e))
        except asyncio.CancelledError:
            sys.exit("unhandled cancel exception")

    @abstractmethod
    async def main_loop_initialize(self, tp: WrappedTransport) -> None:
        sys.exit("not implemented")

    @abstractmethod
    async def main_loop_read(self, tp: WrappedTransport) -> None:
        sys.exit("not implemented")
