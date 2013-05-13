from datetime import datetime

import sys
sys.path.insert(0, "bindings/python/") # XXX
import elliptics

__doc__ = \
"""
XXX:
"""

class Time(object):
    __doc__ = """
                XXX:
              """
    __slots__ = ('time')

    def __init__(self, tsec, tnsec):
        self.time = elliptics.Time(tsec, tnsec)

    @classmethod
    def time_min(cls):
        return cls(0, 0)

    @classmethod
    def time_max(cls):
        return cls(2**64-1, 2**64-1)

    def to_etime(self):
        return self.time

    @classmethod
    def from_epoch(cls, epoch):
        return cls(int(epoch), 0)

    @classmethod
    def from_etime(cls, etime):
        return cls(etime.tsec, etime.tnsec)

    @classmethod
    def from_datetime(cls, dt):
        pass # XXX:

    @classmethod
    def from_string(cls, etime):
        pass # XXX
