import asyncio
import ssl
from util.proxy_protocols import parse_trojan_protocol

from tcp_relays.final_relays.bypass_relay import BypassRelay


class DomainFronter(BypassRelay):

    async def incoming_upgrade(self, timeout,
                               sslcontext, *,
                               server_hostname, ssl_handshake_timeout, ssl_shutdown_timeout):
        self.relay_correct_usage_check()
        try:
            to_return = await self.incoming_tp.upgrade(timeout,
                                                       sslcontext, server_hostname=server_hostname,
                                                       ssl_handshake_timeout=ssl_handshake_timeout,
                                                       ssl_shutdown_timeout=ssl_shutdown_timeout)

        except ssl.SSLError as e:
            p_tj = parse_trojan_protocol(self.gateway_trojan)
            print("INBOUND SSL ERROR: ", repr(e), "sni: ", self.upgrade_incoming_magic["in_sni"], "fake_sni: ",
                  self.upgrade_outgoing_magic["kwargs"]["server_hostname"], "alpn: ",
                  self.upgrade_incoming_magic["in_alpn"], "selected_alpn: ", self.upgrade_incoming_magic["chosen_alpn"],
                  "address_type: ", p_tj["remote_address_type"],
                  "address: ", p_tj["remote_address"], "port: ", p_tj["remote_port"], "client_hello: ",
                  self.upgrade_incoming_magic["repeat_command"])
            self.relay_close()
        except Exception as e:
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

        except ssl.SSLError as e:
            p_tj = parse_trojan_protocol(self.gateway_trojan)
            print("OUTBOUND SSL ERROR: ", repr(e), "sni: ", self.upgrade_incoming_magic["in_sni"], "fake_sni: ",
                  self.upgrade_outgoing_magic["kwargs"]["server_hostname"], "alpn: ",
                  self.upgrade_incoming_magic["in_alpn"],
                  "address_type: ", p_tj["remote_address_type"],
                  "address: ", p_tj["remote_address"], "port: ", p_tj["remote_port"])
            self.relay_close()
        except Exception as e:
            self.relay_close()
        except asyncio.CancelledError:
            self.relay_close()
        else:
            self.relay_correct_usage_check()
            selected_alpn = self.outgoing_tp.get_raw_transport().writer.get_extra_info(
                'ssl_object').selected_alpn_protocol()
            all_out_alpn = self.upgrade_outgoing_magic["out_alpn"]
            if not ((all_out_alpn == ["h2", "http/1.1"] and selected_alpn == "h2") or (
                    all_out_alpn == ["http/1.1"] and selected_alpn == "http/1.1")):
                p_tj = parse_trojan_protocol(self.gateway_trojan)
                print("Info: Special Case Found: ", "sni: ", self.upgrade_incoming_magic["in_sni"], "fake_sni: ",
                      self.upgrade_outgoing_magic["kwargs"]["server_hostname"], "alpn: ",
                      self.upgrade_incoming_magic["in_alpn"], "selected_alpn: ",  selected_alpn,
                      "address_type: ", p_tj["remote_address_type"],
                      "address: ", p_tj["remote_address"], "port: ", p_tj["remote_port"])

            return to_return
