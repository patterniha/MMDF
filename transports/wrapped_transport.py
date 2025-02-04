import sys
import asyncio
import traceback
from transports.transport import Transport
from util.timer import Timer


class WrappedTransport[T: Transport]:

    def __init__(self, raw_transport: T):
        self.loop = asyncio.get_running_loop()
        self._raw_transport = raw_transport
        self.read_upgrade_timer = Timer()
        self.waiting_tasks = set()
        self.created_task: asyncio.Task = asyncio.current_task()
        self.is_writable_from_other_tasks = False

    def get_raw_transport(self) -> T:
        return self._raw_transport

    async def read(self, timeout, *args, **kwargs):
        current_task = asyncio.current_task()
        if current_task != self.created_task:
            sys.exit("read from other task")
        if current_task in self.waiting_tasks:
            sys.exit("Task already waiting!")
        self.waiting_tasks.add(current_task)
        try:
            return await self.read_upgrade_timer.async_watchdog_runner(timeout, self._raw_transport.read, *args,
                                                                       **kwargs)
        finally:
            if current_task not in self.waiting_tasks:
                sys.exit("Task not waiting!")
            self.waiting_tasks.remove(current_task)

    async def write(self, timeout, data, *args, **kwargs):
        if not data:
            sys.exit("no data to write")
        current_task = asyncio.current_task()
        if (not self.is_writable_from_other_tasks) and (current_task != self.created_task):
            sys.exit("not writable from other tasks")
        if current_task in self.waiting_tasks:
            sys.exit("Task already waiting!")
        self.waiting_tasks.add(current_task)
        try:
            return await Timer().async_watchdog_runner(timeout, self._raw_transport.write, data, *args, **kwargs)
        finally:
            if current_task not in self.waiting_tasks:
                sys.exit("Task not waiting!")
            self.waiting_tasks.remove(current_task)

    async def upgrade(self, timeout, *args, **kwargs):
        if (timeout == 0) or (timeout is None):
            sys.exit("upgrade timeout must be positive")
        if self.is_writable_from_other_tasks:
            sys.exit("for upgrade writing from other tasks should be disabled earlier")
        current_task = asyncio.current_task()
        if current_task != self.created_task:
            sys.exit("upgrade out of context")
        if current_task in self.waiting_tasks:
            sys.exit("Task already waiting!")
        self.waiting_tasks.add(current_task)
        try:
            return await self.read_upgrade_timer.async_watchdog_runner(timeout, self._raw_transport.upgrade, *args,
                                                                       **kwargs)
        finally:
            if self.is_writable_from_other_tasks:
                sys.exit("for upgrade writing from other tasks should be disabled earlier!")
            if current_task not in self.waiting_tasks:
                sys.exit("Task not waiting!")
            self.waiting_tasks.remove(current_task)

    def sync_close(self, *args, **kwargs):
        try:
            for task in self.waiting_tasks:
                task.cancel()
            return self._raw_transport.sync_close(*args, **kwargs)
        except Exception as e:
            traceback.print_exc()
            sys.exit(repr(e))

    async def async_close(self, *args, **kwargs):
        return await self._raw_transport.async_close(*args, **kwargs)

    async def wait_closed(self, *args, **kwargs):
        return await self._raw_transport.wait_closed(*args, **kwargs)
