from datetime import datetime

import sys
sys.path.insert(0, "bindings/python/") # XXX
import elliptics

__doc__ = \
    """
    Converters from and to elliptics dnet_time format.
    """

class Time(object):
    __doc__ = \
        """
        Wrapper on top of dnet_time
        """
    __slots__ = ('time')

    def __init__(self, tsec, tnsec):
        self.time = elliptics.Time(tsec, tnsec)

    def __str__(self):
        return "{0}:{1}".format(self.time.tsec, self.time.tnsec)

    def __repr__(self):
        return "Time({0}, {1})".format(self.time.tsec, self.time.tnsec)

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
    def from_string(cls, string):
        pass # XXX
