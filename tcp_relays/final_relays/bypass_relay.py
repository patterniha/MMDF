from tcp_relays.swiss_knife_relay import SwissKnifeRelay


class BypassRelay(SwissKnifeRelay):

    def _init(self):
        pass

    async def incoming_main_loop_read_data_event(self, data: bytes) -> None:
        await self.outgoing_write(data)

    async def outgoing_main_loop_read_data_event(self, data: bytes) -> None:
        await self.incoming_write(data)
