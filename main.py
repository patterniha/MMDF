# @patterniha
import asyncio
import sys
import traceback
from transports.abstract_transport_manager import WrappedTransport
from transports.tcp_stream_transport import TcpStreamTransport, TransportType
from util.proxy_protocols import parse_trojan_protocol
from initialize import listen_host, listen_port, wait_for_trojan_timeout, \
    repeater_domain_front_trojan_hashed_password, private_domain_front_trojan_hashed_password
from controller import Controller


async def trojan_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        incoming_tp = WrappedTransport[TcpStreamTransport](TcpStreamTransport(TransportType.incoming, reader, writer))
        await asyncio.sleep(0.015626)
        try:
            trojan_data = await incoming_tp.read(wait_for_trojan_timeout)
        except Exception as e:
            # print("WARNING READ TROJAN FAILED:", repr(e))
            incoming_tp.sync_close()
            return
        except asyncio.CancelledError:
            print("WARNING READ TROJAN CANCELLED")
            incoming_tp.sync_close()
            return
        try:
            incoming_parsed_tj = parse_trojan_protocol(trojan_data)
        except Exception as e:
            print("WARNING No Trojan Request!, Connection Closed", repr(e), trojan_data)
            incoming_tp.sync_close()
            return

        incoming_payload = trojan_data[incoming_parsed_tj["payload_index"]:]
        if incoming_parsed_tj["transport_protocol"] != "tcp":
            print("WARNING UDP Request Is Not Supported, Connection Closed", incoming_parsed_tj, incoming_payload)
            incoming_tp.sync_close()
            return
        incoming_trojan_hashed_password = incoming_parsed_tj["trojan_hashed_password"]
        if incoming_trojan_hashed_password == private_domain_front_trojan_hashed_password:
            await Controller.on_private_domain_front_request(incoming_tp, incoming_parsed_tj, incoming_payload)
            incoming_tp.sync_close()
            return
        elif incoming_trojan_hashed_password == repeater_domain_front_trojan_hashed_password:
            await Controller.on_repeater_domain_front_request(incoming_tp, incoming_parsed_tj, incoming_payload)
            incoming_tp.sync_close()
            return
        else:
            print("WARNING Unauthenticated Request!, Connection Closed", incoming_parsed_tj, incoming_payload)
            incoming_tp.sync_close()
            return
    except Exception as e:
        traceback.print_exc()
        sys.exit(repr(e))
    except asyncio.CancelledError:
        sys.exit("cancel not allowed!")


async def main():
    server = await asyncio.start_server(
        trojan_handler, listen_host, listen_port, limit=32767)
    async with server:
        print("MMDF started. listening on ", str(listen_host) + ":" + str(listen_port))
        await server.serve_forever()


asyncio.run(main())
