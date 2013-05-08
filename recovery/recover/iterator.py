from .misc import logged_class, mk_container_name
from .time import Time
from .range import IdRange

import sys
sys.path.insert(0, "bindings/python/") # XXX
import elliptics

__doc__ = \
"""
XXX:
"""

class IteratorResult(object):
    __doc__ = """
              Container for iterator results
              Provides status and IteratorResultContainer wrapper.
              """
    def __init__(self, eid=None, id_range=IdRange(None, None), status=False, exception=None, container=None):
        self.eid = eid
        self.id_range = id_range
        self.container = container
        self.status = status
        self.exception = exception
        self.__file = None

    def append(self, record):
        self.container.append(record)

    def sort(self):
        """Sorts results"""
        self.container.sort()

    def diff(self, other):
        """
        Computes diff between two sorted results. Returns container that consists of difference.
        """
        # XXX: Use tmp dir
        filename = mk_container_name(self.id_range, self.eid, prefix='diff_') + '-' + \
                   mk_container_name(other.id_range, other.eid, prefix='')
        diff_container = self.from_filename(filename)
        self.container.diff(other.container, diff_container.container)
        return diff_container

    def __len__(self):
        return self.container.__len__()

    @classmethod
    def from_filename(cls, filename, **kwargs):
        """
        Creates iterator result from filename
        """
        container_file = open(filename, 'w+')
        result = cls.from_fd(container_file.fileno(), **kwargs)
        result.__file = container_file # Save it from python's gc
        return result

    @classmethod
    def from_fd(cls, fd, **kwargs):
        """
        Creates iterator result from fd
        """
        result = cls(**kwargs)
        result.container = elliptics.IteratorResultContainer(fd)
        return result

    def __nonzero__(self):
        return self.status


@logged_class
class Iterator(object):
    def __init__(self, node, group):
        self.session = elliptics.Session(node)
        self.session.set_groups([group])

    def __start(self, eid, request):
        id_range = IdRange(request.key_begin, request.key_end)
        result = IteratorResult.from_filename(mk_container_name(id_range, eid), eid=eid, id_range=id_range)
        iterator = self.session.start_iterator(eid, request)
        for record in iterator:
            if record.status != 0:
                raise RuntimeError("Iteration status check failed: {0}".format(record.status))
            # TODO: Here we can add throttling
            result.append(record)
        result.status = True
        return result

    def start(self,
              eid=elliptics.Id([0]*64, 0, 0),
              itype=elliptics.iterator_types.network,
              flags=elliptics.iterator_flags.key_range|elliptics.iterator_flags.ts_range,
              key_range=(IdRange.ID_MIN, IdRange.ID_MAX),
              timestamp_range=(Time.time_min().to_etime(), Time.time_max().to_etime())):
        """
        XXX:
        """
        assert itype == elliptics.iterator_types.network, "Only network iterator is supported for now" # TODO:
        assert flags & elliptics.iterator_flags.data == 0, "Only metadata iterator is supported for now" # TODO:
        try:
            request = elliptics.IteratorRequest()
            request.action = elliptics.iterator_actions.start
            request.itype = itype
            request.flags = flags
            request.key_begin, request.key_end = key_range
            request.time_begin, request.time_end = timestamp_range
            return self.__start(eid, request)
        except Exception as e:
            self.log.error("Iteration failed: {0}".format(repr(e)))
            return IteratorResult(exception=e)
