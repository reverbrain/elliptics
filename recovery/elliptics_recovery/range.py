# =============================================================================
# 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

"""
Key ranges routines
"""

from collections import namedtuple
from .utils.misc import logged_class
import elliptics


@logged_class
class IdRange(object):
    """
    More python'ish ID ranges
    """
    __slots__ = ('range_id', 'start', 'stop')

    ID_MIN = elliptics.Id([0] * 64, 0)
    ID_MAX = elliptics.Id([255] * 64, 0)

    def __init__(self, start, stop, range_id=0):
        assert start <= stop
        self.start = start
        self.stop = stop
        self.range_id = range_id

    def __iter__(self):
        return iter((self.start, self.stop))

    def __repr__(self):
        return "IdRange({0}, {1}, {2})" .format(self.range_id,
                                                repr(self.start),
                                                repr(self.stop))

    def __str__(self):
        return "{0}@{1}:{2}".format(self.range_id, self.start, self.stop)

    def __eq__(self, other):
        return (self.start, self.stop) == (other.start, other.stop)

    def __ne__(self, other):
        return not self == other

    def __nonzero__(self):
        return not (self.start == self.stop == self.id_min)

    def __hash__(self):
        return hash((tuple(self.start), tuple(self.stop)))

    def check_key(self, key):
        if key < self.start:
            return -1
        if key > self.stop:
            return 1

        return 0

    @staticmethod
    def elliptics_range(key_begin, key_end):
        ret = elliptics.IteratorRange()
        ret.key_begin = key_begin
        ret.key_end = key_end
        return ret

    @classmethod
    def full_range(cls):
        return cls(cls.ID_MIN, cls.ID_MAX)

# Data structure for recovery iterators
RecoveryRange = namedtuple('RecoveryRange', 'id_range address')
AddressRanges = namedtuple('AddressRanges', 'address, eid, id_ranges')
