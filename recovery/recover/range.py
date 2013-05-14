from collections import namedtuple

from .utils.misc import logged_class, format_id

__doc__ = \
    """
    Id range routines
    """

@logged_class
class IdRange(object):
    __doc__ = \
        """
        More python'ish ID ranges
        """
    __slots__ = ('start', 'stop')

    ID_MIN = [0]*64
    ID_MAX = [255]*64

    def __init__(self, start, stop):
        assert start <= stop
        self.start = start
        self.stop = stop

    def __iter__(self):
        return iter((self.start, self.stop))

    def __repr__(self):
        return "IdRange({0}, {1})".format(repr(self.start), repr(self.stop))

    def __str__(self):
        return "{0}:{1}".format(format_id(self.start), format_id(self.stop))

    def __eq__(self, other):
        return self.start == other.start and self.stop == other.stop

    def __nonzero__(self):
        return not (self.start == self.stop == self.id_min)

    def __hash__(self):
        return hash((tuple(self.start), tuple(self.stop)))

    @classmethod
    def full_range(cls):
        return cls(cls.ID_MIN, cls.ID_MAX)

# Data structure for recovery iterators
RecoveryRange = namedtuple('RecoveryRange', 'id_range host')
