import asyncio
import sys
import traceback
from abc import abstractmethod
from util.timer import Timer
from transports.abstract_transport_manager import AbstractTransportManager, WrappedTransport
from transports.tcp_stream_transport import TcpStreamTransport


class TcpToTcpRelay(AbstractTransportManager):
    incoming_tp: WrappedTransport[TcpStreamTransport]
    outgoing_tp: WrappedTransport[TcpStreamTransport] | None
    unbound_tasks: list[asyncio.Task]
    relay_closing: asyncio.Event
    outgoing_sending_buffer: bytearray
    incoming_sending_buffer: bytearray
    main_loop_incoming_read_timeout: float | None
    main_loop_outgoing_read_timeout: float | None
    incoming_write_default_timeout: float | None
    outgoing_write_default_timeout: float | None

    def relay_correct_usage_check(self):
        if self.relay_closing.is_set():
            sys.exit("relay closing")
        if (
                self.outgoing_tp is not None) and self.outgoing_tp.is_writable_from_other_tasks and self.outgoing_sending_buffer:
            sys.exit("outgoing is writable from other tasks but to outgoing buffer is not empty")
        if self.incoming_tp.is_writable_from_other_tasks and self.incoming_sending_buffer:
            sys.exit("incoming is writable from other tasks but to incoming buffer is not empty")

    def relay_close(self):
        try:
            self.relay_closing.set()
            for t in self.unbound_tasks:
                t.cancel()
            self.unbound_tasks.clear()
            self.incoming_tp.sync_close()
            if self.outgoing_tp:
                self.outgoing_tp.sync_close()
        except Exception as e:
            traceback.print_exc()
            sys.exit(repr(e))
        raise self.ExitMainLoop(self)

    def add_to_outgoing_sending_buffer(self, data):
        if not data:
            sys.exit("no data to buffer")
        if (len(data) + len(self.outgoing_sending_buffer)) < 131073:
            self.outgoing_sending_buffer.extend(data)
        else:
            print("relay outgoing sending buffer overflow!", len(data), data[:128], data[-128:])
            self.relay_close()

    def add_to_incoming_sending_buffer(self, data):
        if not data:
            sys.exit("no data to buffer!")
        if (len(data) + len(self.incoming_sending_buffer)) < 131073:
            self.incoming_sending_buffer.extend(data)
        else:
            print("relay incoming sending buffer overflow!", len(data), data[:128], data[-128:])
            self.relay_close()

    async def incoming_write(self, data, timeout=-1):
        if not data:
            sys.exit("no data to write")
        self.relay_correct_usage_check()
        can_send = False
        current_task = asyncio.current_task()
        if current_task == self.incoming_tp.created_task:
            can_send = True
        elif self.outgoing_tp and current_task == self.outgoing_tp.created_task:
            if self.incoming_tp.is_writable_from_other_tasks:
                can_send = True
        else:
            sys.exit("unknown task")
        if can_send:
            if timeout == -1:
                w_timeout = self.incoming_write_default_timeout
            else:
                w_timeout = timeout
            try:
                to_return = await self.incoming_tp.write(w_timeout, data)
            except asyncio.CancelledError:
                self.relay_close()
            except Timer.NoSyncedResult:
                print("WARNING incoming write timeout!", w_timeout)
                self.relay_close()
            except Timer.TimerExpired:
                print("WARNING incoming write timeout!", w_timeout)
                self.relay_close()
            except Exception as e:
                self.relay_close()
            else:
                self.relay_correct_usage_check()
                return to_return
        else:
            self.add_to_incoming_sending_buffer(data)
            self.relay_correct_usage_check()
            return self.incoming_sending_buffer

    async def outgoing_write(self, data, timeout=-1):
        if not data:
            sys.exit("no data to write!")
        self.relay_correct_usage_check()
        can_send = False
        current_task = asyncio.current_task()
        if self.outgoing_tp and current_task == self.outgoing_tp.created_task:
            can_send = True
        elif current_task == self.incoming_tp.created_task:
            if self.outgoing_tp and self.outgoing_tp.is_writable_from_other_tasks:
                can_send = True
        else:
            sys.exit("unknown task")
        if can_send:
            if timeout == -1:
                w_timeout = self.outgoing_write_default_timeout
            else:
                w_timeout = timeout
            try:
                to_return = await self.outgoing_tp.write(w_timeout, data)
            except asyncio.CancelledError:
                self.relay_close()
            except Timer.NoSyncedResult:
                print("WARNING outgoing write timeout!", w_timeout)
                self.relay_close()
            except Timer.TimerExpired:
                print("WARNING outgoing write timeout!", w_timeout)
                self.relay_close()
            except Exception as e:
                self.relay_close()
            else:
                self.relay_correct_usage_check()
                return to_return
        else:
            self.add_to_outgoing_sending_buffer(data)
            self.relay_correct_usage_check()
            return self.outgoing_sending_buffer

    async def incoming_upgrade(self, timeout,
                               sslcontext, *,
                               server_hostname, ssl_handshake_timeout, ssl_shutdown_timeout):
        self.relay_correct_usage_check()
        try:
            to_return = await self.incoming_tp.upgrade(timeout,
                                                       sslcontext, server_hostname=server_hostname,
                                                       ssl_handshake_timeout=ssl_handshake_timeout,
                                                       ssl_shutdown_timeout=ssl_shutdown_timeout)
        except Exception as e:
            # print("upgrade incoming error", repr(e))
            self.relay_close()
        except asyncio.CancelledError:
            self.relay_close()
        else:
            self.relay_correct_usage_check()
            return to_return

    async def outgoing_upgrade(self, timeout,
                               sslcontext, *,
                               server_hostname, ssl_handshake_timeout, ssl_shutdown_timeout):
        self.relay_correct_usage_check()
        try:
            to_return = await self.outgoing_tp.upgrade(timeout,
                                                       sslcontext, server_hostname=server_hostname,
                                                       ssl_handshake_timeout=ssl_handshake_timeout,
                                                       ssl_shutdown_timeout=ssl_shutdown_timeout)
        except Exception as e:
            self.relay_close()
        except asyncio.CancelledError:
            self.relay_close()
        else:
            self.relay_correct_usage_check()
            return to_return

    async def incoming_main_loop_tp_read(self) -> None:
        try:
            data = await self.incoming_tp.read(self.main_loop_incoming_read_timeout)
        except Exception as e:
            self.relay_close()
        except asyncio.CancelledError:
            self.relay_close()
        else:
            self.relay_correct_usage_check()
            await self.incoming_main_loop_read_data_event(data)

    async def outgoing_main_loop_tp_read(self) -> None:
        try:
            data = await self.outgoing_tp.read(self.main_loop_outgoing_read_timeout)
        except Exception as e:
            self.relay_close()
        except asyncio.CancelledError:
            self.relay_close()
        else:
            self.relay_correct_usage_check()
            await self.outgoing_main_loop_read_data_event(data)

    async def main_loop_read(self, tp: WrappedTransport) -> None:
        self.relay_correct_usage_check()
        if tp is self.incoming_tp:
            await self.incoming_main_loop_tp_read()
        elif tp is self.outgoing_tp:
            await self.outgoing_main_loop_tp_read()
        else:
            sys.exit("unknown tp type")

    @abstractmethod
    async def incoming_main_loop_read_data_event(self, data: bytes) -> None:
        sys.exit("not implemented")

    @abstractmethod
    async def outgoing_main_loop_read_data_event(self, data: bytes) -> None:
        sys.exit("not implemented")

    @abstractmethod
    async def incoming_main_loop_initialize(self) -> None:
        sys.exit("not implemented")

    @abstractmethod
    async def outgoing_main_loop_initialize(self) -> None:
        sys.exit("not implemented")

    async def main_loop_initialize(self, tp: WrappedTransport) -> None:
        self.relay_correct_usage_check()
        if tp is self.incoming_tp:
            await self.incoming_main_loop_initialize()
        elif tp is self.outgoing_tp:
            await self.outgoing_main_loop_initialize()
        else:
            sys.exit("unknown tp type")
