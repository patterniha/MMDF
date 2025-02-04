import sys
import asyncio
from abc import abstractmethod
from util.instant_cert_ctx import InstantCertServerSideCtx, get_client_side_ctx
from util.timer import Timer
from transports.wrapped_transport import WrappedTransport
from transports.tcp_stream_transport import TcpStreamTransport
from tcp_relays.middle_bound_no_struggle_one_try_tcp_to_tcp_relay import MiddleBoundNoStruggleOneTryTcpToTcpRelay


class SwissKnifeRelay(MiddleBoundNoStruggleOneTryTcpToTcpRelay):
    gateway_trojan: bytes
    upgrade_incoming_magic: dict | None
    upgrade_outgoing_magic: dict | None
    lazy_mode: int
    pre_read_data: bytes | None

    def __init__(self, incoming_tp: WrappedTransport[TcpStreamTransport],
                 outgoing_tp: WrappedTransport[TcpStreamTransport] | None,
                 gateway_host: str, gateway_port: int,
                 gateway_trojan: bytes,
                 lazy_mode: int, pre_read_data: bytes | None, upgrade_incoming_magic: dict | None,
                 upgrade_outgoing_magic: dict | None,
                 unbound_tasks: list[asyncio.Task], incoming_sending_buffer: bytearray,
                 outgoing_sending_buffer: bytearray,
                 main_loop_incoming_read_timeout, main_loop_outgoing_read_timeout, connect_timer: Timer,
                 local_connect_timeout, incoming_write_default_timeout, outgoing_write_default_timeout, *args,
                 **kwargs):
        self.relay_closing = asyncio.Event()
        self.incoming_tp = incoming_tp
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        if len(gateway_trojan) < 66:
            sys.exit("too short trojan")
        if len(gateway_trojan) >= 65536:
            sys.exit("too long trojan")
        self.gateway_trojan = gateway_trojan
        self.lazy_mode = lazy_mode
        if pre_read_data is not None:
            if not pre_read_data:
                sys.exit("no pre read data if none use None")
            if len(pre_read_data) >= 65536:
                sys.exit("too long pre read data")
        self.pre_read_data = pre_read_data
        self.upgrade_incoming_magic = upgrade_incoming_magic
        self.upgrade_outgoing_magic = upgrade_outgoing_magic
        self.outgoing_tp = outgoing_tp
        self.unbound_tasks = unbound_tasks
        self.outgoing_sending_buffer = outgoing_sending_buffer
        self.incoming_sending_buffer = incoming_sending_buffer
        self.connect_timer = connect_timer
        self.main_loop_incoming_read_timeout = main_loop_incoming_read_timeout
        self.main_loop_outgoing_read_timeout = main_loop_outgoing_read_timeout
        self.local_connect_timeout = local_connect_timeout
        self.incoming_write_default_timeout = incoming_write_default_timeout
        self.outgoing_write_default_timeout = outgoing_write_default_timeout
        self._init(*args, **kwargs)

    @abstractmethod
    def _init(self, *args, **kwargs):
        sys.exit("must implemented in subclass")

    async def outgoing_main_loop_initialize(self):
        if self.outgoing_tp.is_writable_from_other_tasks:
            sys.exit("writable should be locked at initialization")
        is_send_trojan = False
        if self.upgrade_outgoing_magic:
            assert self.upgrade_outgoing_magic["sslcontext"] == -1
            self.upgrade_outgoing_magic["sslcontext"] = get_client_side_ctx(
                self.upgrade_outgoing_magic["check_hostname"], self.upgrade_outgoing_magic["verify_mode"],
                self.upgrade_outgoing_magic["cadata"], self.upgrade_outgoing_magic["out_alpn"])
            await self.outgoing_write(self.gateway_trojan, 0)
            is_send_trojan = True
            await self.outgoing_upgrade(self.upgrade_outgoing_magic["timeout"],
                                        self.upgrade_outgoing_magic["sslcontext"],
                                        **self.upgrade_outgoing_magic["kwargs"])
            self.upgrade_outgoing_magic[
                "selected_alpn"] = self.outgoing_tp.get_raw_transport().writer.get_extra_info(
                'ssl_object').selected_alpn_protocol()
            o_s_alpn = self.upgrade_outgoing_magic["selected_alpn"]
            o_alpn = self.upgrade_outgoing_magic["out_alpn"]
            if not ((o_s_alpn is None) or (o_s_alpn in o_alpn)):
                sys.exit("alpn mismatch!!!")
            if self.upgrade_incoming_magic and self.upgrade_incoming_magic["chosen_alpn"] == -1:
                if self.incoming_tp.is_writable_from_other_tasks:
                    sys.exit("writing from other should be disabled if we should upgrade")
                if not self.incoming_tp.read_upgrade_timer.is_pending():
                    sys.exit("not pending read!")
                if self.incoming_tp.read_upgrade_timer.is_reschedule_able():
                    self.upgrade_incoming_magic["chosen_alpn"] = self.upgrade_outgoing_magic["selected_alpn"]
                    self.incoming_tp.read_upgrade_timer.cancel()
                else:
                    if self.incoming_tp.read_upgrade_timer.expired():
                        print("expired before cancelling")
                        self.relay_close()
                    else:
                        sys.exit("failed cancelling")
        self.outgoing_tp.is_writable_from_other_tasks = True
        if self.outgoing_sending_buffer:
            to_send = bytes(self.outgoing_sending_buffer)
            self.outgoing_sending_buffer.clear()
            if not is_send_trojan:
                await self.outgoing_write(self.gateway_trojan + to_send, 0)
            else:
                await self.outgoing_write(to_send, 0)
        else:
            if not is_send_trojan:
                await self.outgoing_write(self.gateway_trojan, 0)

    async def magic_incoming_tp_upgrade(self):
        chosen_alpn = self.upgrade_incoming_magic["chosen_alpn"]
        if chosen_alpn == -1:
            sys.exit("alpn = -1")
        if not ((chosen_alpn is None) or (chosen_alpn in self.upgrade_incoming_magic["in_alpn"])):
            sys.exit("alpn mismatch!!!!")
        icc: InstantCertServerSideCtx = self.upgrade_incoming_magic["icc"]
        in_sni: str | None = self.upgrade_incoming_magic["in_sni"]
        if in_sni is None:
            ctx = icc.update_cert_and_get_server_side_ctx(self.upgrade_incoming_magic["remote_address_type"],
                                                          self.upgrade_incoming_magic["remote_address"], chosen_alpn)
        else:
            icc.update_cert(self.upgrade_incoming_magic["remote_address_type"],
                            self.upgrade_incoming_magic["remote_address"])
            ctx = icc.update_cert_and_get_server_side_ctx("hostname", in_sni, chosen_alpn)
        assert self.upgrade_incoming_magic["sslcontext"] == -1
        self.upgrade_incoming_magic["sslcontext"] = ctx
        await self.incoming_write(self.upgrade_incoming_magic["repeat_command"], 0)
        await self.incoming_upgrade(self.upgrade_incoming_magic["timeout"],
                                    self.upgrade_incoming_magic["sslcontext"],
                                    **self.upgrade_incoming_magic["kwargs"])
        self.upgrade_incoming_magic["selected_alpn"] = self.incoming_tp.get_raw_transport().writer.get_extra_info(
            'ssl_object').selected_alpn_protocol()
        if chosen_alpn != self.upgrade_incoming_magic["selected_alpn"]:
            sys.exit("alpn mismatch")

    async def incoming_main_loop_initialize(self):
        if self.incoming_tp.is_writable_from_other_tasks:
            sys.exit("writable should be locked at initialization")
        if self.lazy_mode == 1:
            self.ensure_outgoing()
        if self.upgrade_incoming_magic:
            if self.pre_read_data:
                sys.exit("when upgrading all info/data place in magics")
            if self.upgrade_incoming_magic["chosen_alpn"] != -1:
                await self.magic_incoming_tp_upgrade()
            else:
                if not self.upgrade_outgoing_magic:
                    sys.exit("if alpn==-1 means alpn should set by outgoing")
                if self.upgrade_incoming_magic["wait_for_cancel_timeout"] == 0:
                    sys.exit("mean less")
                if self.outgoing_tp:
                    sys.exit("mean less!")
                self.ensure_outgoing()
                try:
                    f_data = await self.incoming_tp.read(self.upgrade_incoming_magic["wait_for_cancel_timeout"])
                except Timer.TimerCancelled as e:
                    if e.timer == self.incoming_tp.read_upgrade_timer:
                        self.relay_correct_usage_check()
                        await self.magic_incoming_tp_upgrade()
                    else:
                        sys.exit("cancelling other timer")
                except Exception as e:
                    self.relay_close()
                except asyncio.CancelledError:
                    self.relay_close()
                else:
                    print("data recv before upgrading! tls-protocol-violation")
                    self.relay_close()
        self.incoming_tp.is_writable_from_other_tasks = True
        if self.incoming_sending_buffer:
            to_send = bytes(self.incoming_sending_buffer)
            self.incoming_sending_buffer.clear()
            await self.incoming_write(to_send, 0)
        if self.lazy_mode == 2:
            self.ensure_outgoing()
        if self.pre_read_data:
            await self.incoming_main_loop_read_data_event(self.pre_read_data)
        if self.lazy_mode == 3:
            self.ensure_outgoing()
