from .misc import logged_class
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
    def __init__(self, eid=None, status=False, exception=None, container=None):
        self.eid = eid
        self.container = container
        self.status = status
        self.exception = exception
        self.file = None

    def sort(self):
        """Sorts results"""
        return self.container.sort()

    def diff(self, r2):
        """
        Computes diff between two sorted results. Returns container that consists of difference.
        """
        return self.container.diff(r2.container)

    @classmethod
    def from_filename(cls, filename, **kwargs):
        """
        Creates iterator result from filename
        """
        container_file = open(filename, 'w+')
        result = cls.from_fd(container_file.fd, **kwargs)
        result.file = container_file # Save it from python's gc
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
        self.log.debug("Creating iterator for node: {0}, group: {1}".format(node, group))
        self.session = elliptics.Session(node)
        self.session.set_groups([group])

    def __start(self, eid, request):
        result = IteratorResult(eid=eid)
        iterator = self.session.start_iterator(eid, request)
        for record in iterator:
            if record.status != 0:
                raise RuntimeError("Iteration status check failed: {0}".format(record.status))
            # Append record to container
            # This only works for network iterator
            self.container.append(record)
        result.status = True
        return result

    def start(self,
              eid=elliptics.Id([0]*64, 0, 0),
              itype=elliptics.iterator_types.network,
              flags=elliptics.iterator_flags.key_range|elliptics.iterator_flags.ts_range,
              key_range=(IdRange.ID_MIN, IdRange.ID_MAX),
              timestamp_range=(Time.time_min().to_etime(), Time.time_max().to_etime())):
        """
        TODO:
        """
        try:
            request = elliptics.IteratorRequest()
            request.itype = itype
            request.flags = flags
            request.key_begin, request.key_end = key_range
            request.time_begin, request.time_end = timestamp_range
            return self.__start(eid, request)
        except Exception as e:
            self.log.error("Iteration failed: {0}".format(repr(e)))
            return IteratorResult(exception=e)
