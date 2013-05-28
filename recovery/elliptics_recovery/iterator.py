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
        Container for iterator results.
        Provides IteratorResultContainer wrapper.
        """
    def __init__(self, eid=None,
                 id_range=IdRange(None, None),
                 address=None,
                 container=None,
                 tmp_dir="",
                 leave_file=False,
    ):
        self.eid = eid
        self.id_range = id_range
        self.address = address
        self.container = container
        self.tmp_dir = tmp_dir
        self.__file = None
        self.leave_file = leave_file

    def __del__(self):
        if self.leave_file:
            return
        self.remove()

    def remove(self):
        try:
            if self.__file:
                from os import unlink
                unlink(self.__file.name)
        except Exception as e:
            self.log.error("Can't remove file: {0}: {1}".format(self.__file.name, e))

    def __len__(self):
        return len(self.container)

    def __iter__(self):
        return iter(self.container)

    def __nonzero__(self):
        return len(self)

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
    def load_filename(cls, filename, sorted, tmp_dir="", **kwargs):
        """
        Creates iterator result from filename
        """
        if tmp_dir:
            filename = os.path.join(tmp_dir, filename)
        container_file = open(filename, 'r+')
        container_file.seek(0, 2)
        result = cls.from_info(container_file.fileno(), sorted, container_file.tell(), tmp_dir="", **kwargs)
        result.__file = container_file # Save it from python's gc
        return result

    @classmethod
    def from_info(cls, fd, sorted, position, **kwargs):
        result = cls(**kwargs)
        result.container = elliptics.IteratorResultContainer(fd, sorted, position)
        return result

    @classmethod
    def from_fd(cls, fd, **kwargs):
        """
        Creates iterator result from fd
        """
        result = cls(**kwargs)
        result.container = elliptics.IteratorResultContainer(fd)
        return result


@logged_class
class Iterator(object):
    __doc__ = \
    """
    Wrapper on top of elliptics new iterator and it's result container
    """
    def __init__(self, node, group):
        self.session = elliptics.Session(node)
        self.session.set_groups([group])

    def start(self,
              eid=elliptics.Id([0]*64, 0, 0),
              itype=elliptics.iterator_types.network,
              flags=elliptics.iterator_flags.key_range|elliptics.iterator_flags.ts_range,
              key_ranges=(IdRange(IdRange.ID_MIN, IdRange.ID_MAX),),
              timestamp_range=(Time.time_min().to_etime(), Time.time_max().to_etime()),
              tmp_dir='/var/tmp',
              address=None,
              leave_file=False,
    ):
        assert itype == elliptics.iterator_types.network, "Only network iterator is supported for now"
        assert flags & elliptics.iterator_flags.data == 0, "Only metadata iterator is supported for now"
        assert len(key_ranges) > 0, "There should be at least one iteration range."

        try:
            start = min(r.start for r in key_ranges)
            stop = max(r.stop for r in key_ranges)
            id_range = IdRange(start, stop)
            filename = os.path.join(tmp_dir, mk_container_name(id_range, eid))
            result = IteratorResult.from_filename(filename,
                                                  address=address,
                                                  id_range=id_range,
                                                  eid=eid,
                                                  tmp_dir=tmp_dir,
                                                  leave_file=leave_file,
            )

            ranges = [IdRange.elliptics_range(start, stop) for start, stop in key_ranges]
            records = self.session.start_iterator(eid, ranges, itype, flags, timestamp_range[0], timestamp_range[1])
            for record in records:
                # TODO: Here we can add throttling
                if record.status != 0:
                    raise RuntimeError("Iteration status check failed: {0}".format(record.status))
                result.append(record)
                # Explicitly delete record
                del record
            return result
        except Exception as e:
            self.log.error("Iteration failed: {0}".format(repr(e)))
            return None
