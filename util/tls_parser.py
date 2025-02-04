import struct
import sys

# from util.hostname_validator import is_valid_no_ip_hostname


def parse_tls_client_hello(data: bytes) -> dict:
    lendata = len(data)
    # assert (lendata > 516) or (lendata < 261)
    assert data[0] == 22 and data[1] == 3 and (data[2] == 1 or data[2] == 3)
    i_protocol_version = data[1:3]
    assert struct.unpack("!H", data[3:5])[0] == lendata - 5
    assert (data[5] == 1) and (data[6] == 0)
    assert struct.unpack("!H", data[7:9])[0] == lendata - 9
    assert data[9] == 3 and data[10] == 3
    client_random = data[11:43]
    # assert data[43] == 32
    sess_len = data[43]
    client_session = data[44:44 + sess_len]
    ciph_ind = 44 + sess_len
    ciphers_bytes_ahead = struct.unpack("!H", data[ciph_ind:ciph_ind + 2])[0]
    assert ciphers_bytes_ahead % 2 == 0
    # assert ciphers_bytes_ahead >= 6
    all_ciphers = []
    fc_ind_ts = ciph_ind + 2
    compression_part_ind = fc_ind_ts + ciphers_bytes_ahead
    while fc_ind_ts < compression_part_ind:
        to_add_cipher = data[fc_ind_ts:fc_ind_ts + 2]
        if to_add_cipher in all_ciphers:
            raise ValueError
        all_ciphers.append(to_add_cipher)
        fc_ind_ts += 2
        assert fc_ind_ts <= compression_part_ind

    # tls13_ciphers = all_ciphers[:3]
    # assert (b"\x13\x01" in tls13_ciphers) and (b"\x13\x02" in tls13_ciphers) and (
    #         b"\x13\x03" in tls13_ciphers)

    assert (data[compression_part_ind] == 1) and (data[compression_part_ind + 1] == 0)
    ext_part_ind = compression_part_ind + 2
    fexh_ind = ext_part_ind + 2
    assert struct.unpack("!H", data[ext_part_ind:fexh_ind])[0] == lendata - fexh_ind

    support_tls13 = False
    sni = None
    padding_len = -1
    alpn = []
    key_shares = dict()
    has_x25519 = False
    extensions_dict = dict()
    while fexh_ind < lendata:
        assert fexh_ind < lendata - 3
        ext_type = data[fexh_ind:fexh_ind + 2]
        ext_length = struct.unpack("!H", data[fexh_ind + 2:fexh_ind + 4])[0]
        if ext_type in extensions_dict.keys():
            raise ValueError

        if ext_type == b"\x00\x00":  # server_name
            assert ext_length > 8
            assert struct.unpack("!H", data[fexh_ind + 4:fexh_ind + 6])[0] == ext_length - 2
            assert data[fexh_ind + 6] == 0
            sni_len = ext_length - 5
            assert struct.unpack("!H", data[fexh_ind + 7:fexh_ind + 9])[0] == sni_len
            sni_ind = fexh_ind + 9
            sni_raw_bytes = data[sni_ind:sni_ind + sni_len]
            sni = sni_raw_bytes.decode()
            assert len(sni) == sni_len


        elif ext_type == b"\x00\x2b":  # supported version
            second_len = data[fexh_ind + 4]
            assert (second_len == ext_length - 1) and (second_len >= 2) and (second_len % 2 == 0)
            ver_ind = fexh_ind + 5
            finn = ver_ind + second_len
            while ver_ind < finn:
                if (data[ver_ind], data[ver_ind + 1]) == (3, 4):
                    support_tls13 = True
                    assert sess_len == 32
                ver_ind += 2
                assert ver_ind <= finn
        elif ext_type == b"\x00\x10":  # alpn
            second_len = struct.unpack("!H", data[fexh_ind + 4:fexh_ind + 6])[0]
            assert (second_len == ext_length - 2) and (second_len > 1)
            see_ind = fexh_ind + 6
            alpn_data_ind = see_ind
            finn = see_ind + second_len
            while see_ind < finn:
                this_alpn_len = data[see_ind]
                assert this_alpn_len > 0
                end_of_this = see_ind + 1 + this_alpn_len
                alpn.append(data[see_ind + 1:end_of_this].decode())
                see_ind = end_of_this
                assert see_ind <= finn

        elif ext_type == b"\x00\x33":  # key_share
            second_len = struct.unpack("!H", data[fexh_ind + 4:fexh_ind + 6])[0]
            assert (second_len == ext_length - 2) and (second_len > 35)
            see_ind = fexh_ind + 6
            finn = see_ind + second_len
            while see_ind < finn:
                key_group = data[see_ind:see_ind + 2]
                key_length = struct.unpack("!H", data[see_ind + 2:see_ind + 4])[0]
                assert key_length > 0
                key_data_ind = see_ind + 4
                end_of_this = key_data_ind + key_length
                key_value = data[key_data_ind:end_of_this]
                if key_group in key_shares.keys():
                    raise ValueError
                key_shares[key_group] = (key_length, key_data_ind, key_value)
                see_ind = end_of_this
                assert see_ind <= finn
                if key_group == b"\x00\x1d":
                    assert key_length == 32
                    has_x25519 = True

        elif ext_type == b"\x00\x15":  # padding
            # padding_data_ind = fexh_ind + 4
            padding_len = ext_length
            # end_of_padding = padding_data_ind + padding_len
            # assert (padding_len > 0) and (padding_len < 253) and (lendata > 516)
            # assert (lendata - (padding_len + 4)) < 517
            # if padding_len > 1:
            #     assert lendata == 517
            # assert data[padding_data_ind:end_of_padding] == b"\x00" * padding_len

        extensions_dict[ext_type] = (ext_length, fexh_ind + 4)
        fexh_ind += 4 + ext_length
        assert fexh_ind <= lendata

    return {"i_protocol_version": i_protocol_version, "client_random": client_random, "client_session": client_session,
            "all_ciphers": all_ciphers, "sni": sni,
            "padding_len": padding_len, "alpn": alpn, "key_shares": key_shares, "extensions_dict": extensions_dict,
            "ext_part_ind": ext_part_ind, "support_tls13": support_tls13, "has_x25519": has_x25519}


# def parse_and_check_is_normal_tls_client_hello(data: bytes) -> tuple[bool, int, dict]:
#     if not data:
#         sys.exit("no data to tls parse!")
#     try:
#         parsed_tls = parse_tls_client_hello(data)
#     except Exception:
#         return False, -1, {}
#     # if parsed_tls["i_protocol_version"] != b"\x03\x01":
#     #     return False, 1, parsed_tls
#     # if not parsed_tls["support_tls13"]:
#     #     return False, 2, parsed_tls
#     # if not parsed_tls["has_x25519"]:
#     #     return False, 3, parsed_tls
#     # in_sni = parsed_tls["sni"]
#     # if in_sni is None:
#     #     return False, 4, parsed_tls
#     # if not is_valid_no_ip_hostname(in_sni, False, False):
#     #     return False, 5, parsed_tls
#     # in_alpn = parsed_tls["alpn"]
#     # if (in_alpn != ["http/1.1"]) and (in_alpn != ["h2", "http/1.1"]):
#     #     return False, 6, parsed_tls
#     return True, 0, parsed_tls
