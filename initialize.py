import json
import sys
import os
import ipaddress
import traceback

from cryptography.hazmat.primitives import hashes


# from util.hostname_validator import is_valid_no_ip_hostname

def _get_loopback_connect_host(f_listen_host):
    try:
        if (f_listen_host == "") or (f_listen_host is None) or (f_listen_host == "0.0.0.0"):
            return "127.0.0.1"
        try:
            if ipaddress.ip_address(f_listen_host) == ipaddress.ip_address("::"):
                return "::1"
        except ValueError:
            pass
        try:
            if (ipaddress.ip_address(f_listen_host[1:-1]) == ipaddress.ip_address("::")) and (f_listen_host[0] == "[") and (
                    f_listen_host[-1] == "]"):
                return "::1"
        except ValueError:
            pass
        return f_listen_host
    except Exception as e:
        traceback.print_exc()
        sys.exit(repr(e))


with open(os.path.join(os.path.dirname(sys.argv[0]), "config.json")) as f:
    _config = json.loads(f.read())

listen_host = _config["listen_host"]
listen_port = _config["listen_port"]
loopback_connect_host = _get_loopback_connect_host(listen_host)
_df = hashes.Hash(hashes.SHA224())
_df.update(_config["listen_trojan_password"].encode())
repeater_domain_front_trojan_hashed_password = _df.finalize()

main_gateway_host = _config["main_gateway_host"]
main_gateway_port = _config["main_gateway_port"]
_main_gateway_h = hashes.Hash(hashes.SHA224())
_main_gateway_h.update(_config["main_gateway_trojan_password"].encode())
main_gateway_trojan_hashed_password = _main_gateway_h.finalize()

bypass_gateway_host = _config["bypass_gateway_host"]
bypass_gateway_port = _config["bypass_gateway_port"]
_bypass_gateway_h = hashes.Hash(hashes.SHA224())
_bypass_gateway_h.update(_config["bypass_gateway_trojan_password"].encode())
bypass_gateway_trojan_hashed_password = _bypass_gateway_h.finalize()

issuer_cert_path = _config["issuer_certificate_path"]
issuer_private_key_path = _config["issuer_private_key_path"]
issuer_private_key_pass = _config["issuer_private_key_pass"]

instant_certificate_temp_file_path = _config["instant_certificate_temp_file_path"]

fake_sni = _config["fake_sni"]
if fake_sni != "random":
    # if not is_valid_no_ip_hostname(fake_sni, False, False):
    #     sys.exit("wrong fake_sni")
    fake_sni_tld = ""
    pure_fake_sni_length_min = pure_fake_sni_length_max = -1

else:
    fake_sni_tld = _config["fake_sni_tld"]
    # if not is_valid_no_ip_hostname("a" + fake_sni_tld, False, False):
    #     sys.exit("wrong fake_sni_tld")
    _fi_s = _config["full_fake_sni_length"].split("-")
    pure_fake_sni_length_min = int(_fi_s[0]) - len(fake_sni_tld)
    pure_fake_sni_length_max = int(_fi_s[1]) - len(fake_sni_tld)
    if pure_fake_sni_length_max < pure_fake_sni_length_min:
        sys.exit("wrong pure_fake_sni_length")
    if pure_fake_sni_length_min < 1:
        sys.exit("wrong pure_fake_sni_length")

#####
_df2 = hashes.Hash(hashes.SHA224())
_df2.update("my_private_pass".encode())
private_domain_front_trojan_hashed_password = _df2.finalize()
wait_for_trojan_timeout = 2
local_connect_timeout = 2
upgrade_incoming_timeout = 2
upgrade_incoming_handshake_timeout = 2
upgrade_incoming_shutdown_timeout = 2
others_connect_upgrade_timeout = 30
others_connect_upgrade_handshake_timeout = 30
others_connect_upgrade_shutdown_timeout = 30
incoming_wait_for_cancel_timeout = 30
incoming_write_timeout = None
outgoing_write_timeout = None

if len(frozenset((main_gateway_trojan_hashed_password, bypass_gateway_trojan_hashed_password,
                  repeater_domain_front_trojan_hashed_password,
                  private_domain_front_trojan_hashed_password))) != 4:
    sys.exit("trojan passwords are not unique")
