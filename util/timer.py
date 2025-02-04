import asyncio
import sys
from enum import IntEnum


class WatchdogResultType(IntEnum):
    success = 0
    timeout_error = 1
    other_exceptions = 2


class Timer:
    class TimerExpired(Exception):
        def __init__(self, timer: "Timer"):
            self.timer = timer

    class NoSyncedResult(Exception):
        def __init__(self, timer: "Timer"):
            self.timer = timer

    class TimerCancelled(Exception):
        def __init__(self, timer: "Timer"):
            self.timer = timer

    class TimerCancelledButSoonerResult(Exception):
        def __init__(self, timer: "Timer", result_type: WatchdogResultType, result):
            self.timer = timer
            self.result_type = result_type
            self.result = result

    @staticmethod
    def get_at_timeout(timeout):
        if timeout is None:
            return None
        elif timeout == 0:
            return 0
        elif timeout < 0:
            sys.exit("timeout must be >= 0 or None")
        elif timeout > 0:
            return timeout + asyncio.get_running_loop().time()
        else:
            sys.exit("timeout must be >= 0 or None")

    def __init__(self):
        self._cm: asyncio.Timeout | None = None
        self._cancelled: bool | None = None

    def is_pending(self):
        if self._cm:
            if self._cancelled is None:
                sys.exit("cm but not cancelled")
            return True
        if self._cancelled is not None:
            sys.exit("cancelled but not cm")
        return False

    def _set(self, timeout):
        if self.is_pending():
            sys.exit("set pending timer")
        try:
            self._cm = asyncio.Timeout(self.get_at_timeout(timeout))
        except Exception as e:
            sys.exit(repr(e))
        self._cancelled = False
        return self._cm

    def _clear(self):
        if not self.is_pending():
            sys.exit("clear not pending timer")
        self._cm = None
        self._cancelled = None

    def is_cancelled(self) -> bool:
        if not self.is_pending():
            sys.exit("no cm")
        return self._cancelled

    def when(self):
        if not self.is_pending():
            sys.exit("when while not pending")
        return self._cm.when()

    def expired(self):
        if not self.is_pending():
            sys.exit("expired not pending")
        return self._cm.expired()

    def is_reschedule_able(self):
        if not self.is_pending():
            sys.exit("no cm")
        if self._cm.expired():
            return False
        if self._cm.when() == 0:
            return False
        return True

    def reschedule(self, timeout):
        if not self.is_pending():
            sys.exit("no cm")
        if not self.is_reschedule_able():
            sys.exit("cannot reschedule timer")
        if timeout == 0:
            sys.exit("use cancel for cancelling timer")
        try:
            self._cm.reschedule(self.get_at_timeout(timeout))
        except Exception as e:
            sys.exit(repr(e))

    def cancel(self):
        if not self.is_pending():
            sys.exit("no cm")
        if not self.is_reschedule_able():
            sys.exit("cannot reschedule timer")
        try:
            self._cm.reschedule(0)
        except Exception as e:
            sys.exit(repr(e))
        self._cancelled = True

    async def async_watchdog_runner(self, timeout, func, *args, **kwargs):
        try:
            async with self._set(timeout):
                to_return = await func(*args, **kwargs)
        except TimeoutError as e:
            if self.expired():
                if self.is_cancelled():
                    raise self.TimerCancelled(self)
                if self.when() == 0:
                    raise self.NoSyncedResult(self)
                raise self.TimerExpired(self)
            if self.is_cancelled():
                raise self.TimerCancelledButSoonerResult(self, WatchdogResultType.timeout_error, e)
            raise e
        except Exception as e:
            if self.expired():
                sys.exit(repr(e))
            if self.is_cancelled():
                raise self.TimerCancelledButSoonerResult(self, WatchdogResultType.other_exceptions, e)
            raise e
        else:
            if self.expired():
                sys.exit("expired with result")
            if self.is_cancelled():
                raise self.TimerCancelledButSoonerResult(self, WatchdogResultType.success, to_return)
            return to_return
        finally:
            self._clear()
