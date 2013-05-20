import sys
import os

from .utils.misc import logged_class, mk_container_name, format_id
from .time import Time
from .range import IdRange

sys.path.insert(0, "bindings/python/") # XXX
import elliptics

__doc__ = \
    """
    Wrappers for iterator and it's result container
    """

@logged_class
class IteratorResult(object):
    __doc__ = \
        """
        Container for iterator results
        Provides status and IteratorResultContainer wrapper.
        """
    def __init__(self, eid=None,
                 id_range=IdRange(None, None),
                 address=None,
                 status=False,
                 exception=None,
                 container=None,
                 tmp_dir="",
    ):
        self.eid = eid
        self.id_range = id_range
        self.address = address
        self.container = container
        self.status = status
        self.exception = exception
        self.tmp_dir = tmp_dir
        self.__file = None

    def __del__(self):
        try:
            if self.__file:
                os.unlink(self.__file.name)
        except Exception as e:
            self.log.error("Can't remove file: {0}: {1}".format(self.__file.name, e))

    def append(self, record):
        self.container.append(record)

    def sort(self):
        """Sorts results"""
        self.container.sort()

    def diff(self, other):
        """
        Computes diff between two sorted results. Returns container that consists of difference.
        """
        filename = 'diff_' + str(self.id_range) + '_' + \
                   format_id(self.eid.id) + '-' + format_id(other.eid.id)
        diff_container = self.from_filename(filename,
                                            eid=other.eid,
                                            id_range=other.id_range,
                                            address=other.address,
                                            tmp_dir=self.tmp_dir,
                                            )
        self.container.diff(other.container, diff_container.container)
        return diff_container

    def __len__(self):
        return len(self.container)

    def __iter__(self):
        return iter(self.container)

    @classmethod
    def from_filename(cls, filename, tmp_dir="", **kwargs):
        """
        Creates iterator result from filename
        """
        if tmp_dir:
            filename = os.path.join(tmp_dir, filename)
        container_file = open(filename, 'w+')
        result = cls.from_fd(container_file.fileno(), tmp_dir=tmp_dir, **kwargs)
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
    __doc__ = \
    """
    Wrapper on top of elliptics new iterator and it's result container
    """
    def __init__(self, node, group):
        self.session = elliptics.Session(node)
        self.session.set_groups([group])

    def __start(self, eid, address, request, tmp_dir):
        id_range = IdRange(request.key_begin, request.key_end)
        filename = os.path.join(tmp_dir, mk_container_name(id_range, eid))
        result = IteratorResult.from_filename(filename, address=address, eid=eid, id_range=id_range, tmp_dir=tmp_dir)
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
              timestamp_range=(Time.time_min().to_etime(), Time.time_max().to_etime()),
              tmp_dir='/var/tmp',
              address=None,
    ):
        """
        Prepare iterator request structure and pass it to low-level __start() function.
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
            return self.__start(eid, address, request, tmp_dir)
        except Exception as e:
            self.log.error("Iteration failed: {0}".format(repr(e)))
            return IteratorResult(exception=e)
