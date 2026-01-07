import ssl
import string
import random
import secrets
from util.instant_cert_ctx import InstantCertServerSideCtx
from util.proxy_protocols import struct_pure_tcp_trojan
from util.tls_parser import parse_tls_client_hello
from util.timer import Timer
from transports.wrapped_transport import WrappedTransport
from transports.tcp_stream_transport import TcpStreamTransport
from tcp_relays.final_relays.bypass_relay import BypassRelay
from tcp_relays.final_relays.one_repeater import OneRepeater
from tcp_relays.final_relays.domain_fronter import DomainFronter
from initialize import issuer_private_key_pass, issuer_private_key_path, issuer_cert_path, \
    main_gateway_host, \
    main_gateway_port, main_gateway_trojan_hashed_password, bypass_gateway_host, bypass_gateway_port, \
    bypass_gateway_trojan_hashed_password, local_connect_timeout, \
    loopback_connect_host, listen_port, upgrade_incoming_timeout, upgrade_incoming_handshake_timeout, \
    upgrade_incoming_shutdown_timeout, others_connect_upgrade_timeout, others_connect_upgrade_handshake_timeout, \
    others_connect_upgrade_shutdown_timeout, incoming_write_timeout, outgoing_write_timeout, \
    private_domain_front_trojan_hashed_password, fake_sni, fake_sni_tld, pure_fake_sni_length_min, \
    pure_fake_sni_length_max, incoming_wait_for_cancel_timeout, instant_certificate_temp_file_path, max_san_list_size


class Controller:
    icc = InstantCertServerSideCtx(issuer_cert_path, issuer_private_key_path, issuer_private_key_pass,
                                   instant_certificate_temp_file_path, max_san_list_size)

    @staticmethod
    def get_fake_sni():
        if fake_sni != "random":
            return fake_sni
        n = random.randint(pure_fake_sni_length_min, pure_fake_sni_length_max)
        return (''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n))) + fake_sni_tld

    @classmethod
    async def on_repeater_domain_front_request(cls, incoming_tp: WrappedTransport[TcpStreamTransport],
                                               incoming_parsed_tj, incoming_payload: bytes):

        try:
            parsed_tls = parse_tls_client_hello(incoming_payload)
        except Exception:
            gateway_trojan = struct_pure_tcp_trojan(bypass_gateway_trojan_hashed_password,
                                                    incoming_parsed_tj["remote_address_type"],
                                                    incoming_parsed_tj["remote_address"],
                                                    incoming_parsed_tj["remote_port"])
            bypass_relay = BypassRelay(incoming_tp, None, bypass_gateway_host, bypass_gateway_port,
                                       gateway_trojan, 3, incoming_payload,
                                       None, None,
                                       list(), bytearray(), bytearray(),
                                       None, None, Timer(), local_connect_timeout, incoming_write_timeout,
                                       outgoing_write_timeout)
            print("Non-TLS Request Bypassed", incoming_parsed_tj["remote_address_type"], incoming_parsed_tj["remote_address"],
                  incoming_parsed_tj["remote_port"], incoming_payload)
            await bypass_relay.main_loop(incoming_tp)
            incoming_tp.sync_close()
            return
        else:
            gateway_trojan = struct_pure_tcp_trojan(private_domain_front_trojan_hashed_password,
                                                    incoming_parsed_tj["remote_address_type"],
                                                    incoming_parsed_tj["remote_address"],
                                                    incoming_parsed_tj["remote_port"])
            one_repeater_relay = OneRepeater(incoming_tp, None, loopback_connect_host, listen_port,
                                             gateway_trojan, -1, incoming_payload,
                                             None, None,
                                             list(), bytearray(), bytearray(),
                                             None, None, Timer(), local_connect_timeout, incoming_write_timeout,
                                             outgoing_write_timeout)
            await one_repeater_relay.main_loop(incoming_tp)
            incoming_tp.sync_close()
            return

    @classmethod
    async def on_private_domain_front_request(cls, incoming_tp: WrappedTransport[TcpStreamTransport],
                                              incoming_parsed_tj, incoming_payload: bytes):

        try:
            parsed_tls = parse_tls_client_hello(incoming_payload)
        except Exception:
            print("!!!CRITICAL WARNING!!! non-tls in private.", incoming_parsed_tj, incoming_payload)
            incoming_tp.sync_close()
            return
        gateway_trojan = struct_pure_tcp_trojan(main_gateway_trojan_hashed_password,
                                                incoming_parsed_tj["remote_address_type"],
                                                incoming_parsed_tj["remote_address"],
                                                incoming_parsed_tj["remote_port"])
        upgrade_incoming_magic = {"in_alpn": parsed_tls["alpn"], "in_sni": parsed_tls["sni"], "icc": cls.icc,
                                  "chosen_alpn": -1, "wait_for_cancel_timeout": incoming_wait_for_cancel_timeout,
                                  "remote_address_type": incoming_parsed_tj["remote_address_type"],
                                  "remote_address": incoming_parsed_tj["remote_address"],
                                  "repeat_command": incoming_payload, "timeout": upgrade_incoming_timeout,
                                  "sslcontext": -1, "kwargs": {"server_hostname": None,
                                                               "ssl_handshake_timeout": upgrade_incoming_handshake_timeout,
                                                               "ssl_shutdown_timeout": upgrade_incoming_shutdown_timeout}}
        upgrade_outgoing_magic = {"sslcontext": -1, "check_hostname": False, "verify_mode": ssl.CERT_NONE,
                                  "cadata": None,
                                  "out_alpn": parsed_tls["alpn"], "timeout": others_connect_upgrade_timeout,
                                  "kwargs": {"server_hostname": cls.get_fake_sni(),
                                             "ssl_handshake_timeout": others_connect_upgrade_handshake_timeout,
                                             "ssl_shutdown_timeout": others_connect_upgrade_shutdown_timeout}}
        domain_front_relay = DomainFronter(incoming_tp, None, main_gateway_host, main_gateway_port,
                                           gateway_trojan, -1, None,
                                           upgrade_incoming_magic, upgrade_outgoing_magic,
                                           list(), bytearray(), bytearray(),
                                           None, None, Timer(), local_connect_timeout, incoming_write_timeout,
                                           outgoing_write_timeout)

        await domain_front_relay.main_loop(incoming_tp)
        incoming_tp.sync_close()
        return
