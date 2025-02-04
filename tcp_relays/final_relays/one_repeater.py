import sys

from tcp_relays.swiss_knife_relay import SwissKnifeRelay


class OneRepeater(SwissKnifeRelay):

    def _init(self):
        self.done_repeat = False
        self.first_data_send: bytes | None = None

    async def incoming_main_loop_read_data_event(self, data: bytes) -> None:
        if self.done_repeat:
            await self.outgoing_write(data)
        else:
            if self.first_data_send is None:
                self.first_data_send = data
                await self.outgoing_write(data, 0)
            else:
                print("tls-protocol-violation!", data)
                self.relay_close()

    async def outgoing_main_loop_read_data_event(self, data: bytes) -> None:
        if self.done_repeat:
            await self.incoming_write(data)
        else:
            if self.first_data_send is None:
                sys.exit("impossible recv data from outgoing before send data")
            else:
                if data != self.first_data_send:
                    print("confirm data failed", self.first_data_send, data)
                    self.relay_close()
                self.done_repeat = True
                await self.outgoing_write(data, 0)
