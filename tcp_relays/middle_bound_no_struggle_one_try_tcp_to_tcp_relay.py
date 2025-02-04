import asyncio
import sys
import traceback
from tcp_relays.tcp_to_tcp_relay import TcpToTcpRelay
from transports.tcp_stream_transport import TcpStreamTransport
from util.timer import Timer, WatchdogResultType
from transports.wrapped_transport import WrappedTransport, Transport


class MiddleBoundNoStruggleOneTryTcpToTcpRelay(TcpToTcpRelay):
    connect_timer: Timer
    gateway_host: str
    gateway_port: int
    local_connect_timeout: float

    def ensure_outgoing(self):
        if (not self.outgoing_tp) and (not self.unbound_tasks) and (not self.connect_timer.is_pending()):
            self.unbound_tasks.append(asyncio.create_task(self.middle_bound_no_struggle_one_try_create_outgoing()))

    def add_to_outgoing_sending_buffer(self, data):
        super().add_to_outgoing_sending_buffer(data)
        self.ensure_outgoing()

    async def middle_bound_no_struggle_one_try_create_outgoing(self):
        """
        this is simple generator made only for middle bound.
        for out-bound we have struggle(and select first), variable connect timeout, other-connect-kwargs, connect_type, ...
        :return:
        """
        try:
            if self.local_connect_timeout == 0 or self.local_connect_timeout is None:
                sys.exit("bad local connect timeout")
            if asyncio.current_task() not in self.unbound_tasks:
                sys.exit("task not in unbound_tasks")
            self.relay_correct_usage_check()
            if self.outgoing_tp:
                sys.exit("create while exist")
            try:
                o_raw_transport = await self.connect_timer.async_watchdog_runner(self.local_connect_timeout,
                                                                                 TcpStreamTransport.connect,
                                                                                 self.gateway_host,
                                                                                 self.gateway_port)
            except Exception as e:
                print("local connect exception", repr(e), self.local_connect_timeout, self.gateway_host,
                      self.gateway_port)
                self.relay_close()
            except asyncio.CancelledError:
                # print("local connect cancelled", self.relay_closing.is_set(), self.local_connect_timeout,
                #       self.gateway_host, self.gateway_port)
                self.relay_close()
            else:
                if self.outgoing_tp:
                    sys.exit("generate while exist")
                self.relay_correct_usage_check()
                self.outgoing_tp = WrappedTransport[TcpStreamTransport](o_raw_transport)
                try:
                    self.unbound_tasks.remove(asyncio.current_task())
                    assert asyncio.current_task() not in self.unbound_tasks
                    assert not self.unbound_tasks
                except Exception as e:
                    traceback.print_exc()
                    sys.exit(repr(e))
                await self.main_loop(self.outgoing_tp)
                self.relay_close()
        except self.ExitMainLoop as e:
            if (e.created_task is asyncio.current_task()) and (e.transport_manager is self):
                return
            sys.exit("irrelevant exception")
        except Exception as e:
            traceback.print_exc()
            sys.exit(repr(e))
        except asyncio.CancelledError:
            sys.exit("cancel not allowed")
