import struct
import socket
import sys


# xray-core vless BUG: in vless use mux for some udp even mux is off --> use trojan for mycustom-xray connection
# trojan adv: more compatible, no mux switch problem, no two additional bytes in first s-to-c packet
# vless adv: more compact in request and udp-data, support mux;padding-in-request;option
def parse_proxy_protocol(data: bytes, proxy_protocol_name: str):
    if not data:
        sys.exit("no data to parse")

    portInd = -1
    if proxy_protocol_name == "vless":
        if len(data) < 24:
            raise ValueError
        version = data[0]
        proxy_authentication = data[1:17]
        optlen = data[17]
        if optlen != 0:
            raise ValueError
        protocol_code = data[18 + optlen]
        portInd = 19 + optlen
        remote_address_type_code = data[21 + optlen]
        addressValueInd = optlen + 22
        tcp_protocol_code = 1
        udp_protocol_code = 2
        # mux: 3 not supported yet, vless-bug-in-xray: mux enabled wrongly in some scenario even mux is off
        ipv4_type = 1
        hostname_type = 2
        ipv6_type = 3
    elif proxy_protocol_name == "trojan":
        if len(data) < 66:
            raise ValueError
        if (data[56] != 0x0d) or (data[57] != 0x0a):
            raise ValueError
        version = 0
        proxy_authentication = bytes.fromhex(data[:56].decode())
        protocol_code = data[58]
        remote_address_type_code = data[59]
        addressValueInd = 60
        tcp_protocol_code = 1
        udp_protocol_code = 3
        ipv4_type = 1
        hostname_type = 3
        ipv6_type = 4
    else:
        sys.exit("unsupported proxy protocol")
    if protocol_code == tcp_protocol_code:
        transport_protocol = "tcp"
    elif protocol_code == udp_protocol_code:
        transport_protocol = "udp"
    else:
        raise ValueError("unsupported protocol")

    if remote_address_type_code == ipv4_type:
        remote_address_type = "ipv4"
        afterAddrInd = addressValueInd + 4
        remote_address = socket.inet_ntop(socket.AF_INET, data[addressValueInd:afterAddrInd])
    elif remote_address_type_code == ipv6_type:
        remote_address_type = "ipv6"
        afterAddrInd = addressValueInd + 16
        remote_address = socket.inet_ntop(socket.AF_INET6, data[addressValueInd:afterAddrInd])
    elif remote_address_type_code == hostname_type:
        remote_address_type = "hostname"
        hostlen = data[addressValueInd]
        hostInd = addressValueInd + 1
        afterAddrInd = hostInd + hostlen
        remote_address = data[hostInd:afterAddrInd].decode()
    else:
        raise ValueError

    if not remote_address:
        raise ValueError

    if proxy_protocol_name == "vless":
        payload_index = afterAddrInd
    elif proxy_protocol_name == "trojan":
        if (data[afterAddrInd + 2] != 0x0d) or (data[afterAddrInd + 3] != 0x0a):
            raise ValueError
        portInd = afterAddrInd
        payload_index = afterAddrInd + 4
    else:
        sys.exit("unsupported proxy protocol")

    if payload_index > len(data):
        raise ValueError

    remote_port = struct.unpack("!H", data[portInd:portInd + 2])[0]

    return {"version": version, "proxy_authentication": proxy_authentication, "transport_protocol": transport_protocol,
            "remote_address_type": remote_address_type,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "payload_index": payload_index}


def parse_trojan_protocol(data: bytes):
    if not data:
        sys.exit("no data to parse")
    if len(data) < 66:
        raise ValueError
    if (data[56] != 0x0d) or (data[57] != 0x0a):
        raise ValueError
    trojan_hashed_password = bytes.fromhex(data[:56].decode())
    protocol_code = data[58]
    remote_address_type_code = data[59]
    address_value_ind = 60
    tcp_protocol_code = 1
    udp_protocol_code = 3
    ipv4_type = 1
    hostname_type = 3
    ipv6_type = 4
    if protocol_code == tcp_protocol_code:
        transport_protocol = "tcp"
    elif protocol_code == udp_protocol_code:
        transport_protocol = "udp"
    else:
        raise ValueError("unsupported protocol")

    if remote_address_type_code == ipv4_type:
        remote_address_type = "ipv4"
        after_addr_ind = address_value_ind + 4
        remote_address = socket.inet_ntop(socket.AF_INET, data[address_value_ind:after_addr_ind])
    elif remote_address_type_code == ipv6_type:
        remote_address_type = "ipv6"
        after_addr_ind = address_value_ind + 16
        remote_address = socket.inet_ntop(socket.AF_INET6, data[address_value_ind:after_addr_ind])
    elif remote_address_type_code == hostname_type:
        remote_address_type = "hostname"
        host_len = data[address_value_ind]
        host_ind = address_value_ind + 1
        after_addr_ind = host_ind + host_len
        remote_address = data[host_ind:after_addr_ind].decode()
    else:
        raise ValueError
    if not remote_address:
        raise ValueError
    if (data[after_addr_ind + 2] != 0x0d) or (data[after_addr_ind + 3] != 0x0a):
        raise ValueError
    port_ind = after_addr_ind
    payload_index = after_addr_ind + 4
    if payload_index > len(data):
        raise ValueError
    remote_port = struct.unpack("!H", data[port_ind:port_ind + 2])[0]
    return {"trojan_hashed_password": trojan_hashed_password, "transport_protocol": transport_protocol,
            "remote_address_type": remote_address_type,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "payload_index": payload_index}


def struct_pure_tcp_trojan(trojan_hashed_password: bytes, remote_address_type: str, remote_address: str,
                           remote_port: int) -> bytes:
    if len(trojan_hashed_password) != 28:
        sys.exit("wrong_hpass")
    b_hex_hashed_pass = trojan_hashed_password.hex().encode()
    b_tcp_mode = b"\x01"
    if remote_address_type == "ipv4":
        b_address_type = b"\x01"
        b_address = socket.inet_pton(socket.AF_INET, remote_address)
    elif remote_address_type == "ipv6":
        b_address_type = b"\x04"
        b_address = socket.inet_pton(socket.AF_INET6, remote_address)
    elif remote_address_type == "hostname":
        b_address_type = b"\x03" + struct.pack("!B", len(remote_address))
        b_address = remote_address.encode()
    else:
        sys.exit("bad address_type")
    b_port = struct.pack("!H", remote_port)
    return b_hex_hashed_pass + b"\r\n" + b_tcp_mode + b_address_type + b_address + b_port + b"\r\n"
