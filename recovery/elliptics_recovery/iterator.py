"""
Wrappers for iterator and it's result container
"""

import sys
import os

from .utils.misc import logged_class, mk_container_name, format_id
from .etime import Time
from .range import IdRange

sys.path.insert(0, "bindings/python/")  # XXX
import elliptics


@logged_class
class IteratorResult(object):
    __doc__ = \
        """
        Container for iterator results.
        Provides IteratorResultContainer wrapper.
        """

    def __init__(self,
                 eid=None,
                 id_range=IdRange(None, None),
                 address=None,
                 container=None,
                 tmp_dir="",
                 leave_file=False,
                 filename=""
                 ):
        self.eid = eid
        self.id_range = id_range
        self.address = address
        self.container = container
        self.tmp_dir = tmp_dir
        self.__file = None
        self.leave_file = leave_file
        self.filename = filename

    def __del__(self):
        if self.leave_file:
            return
        self.remove()

    def remove(self):
        try:
            if self.__file:
                os.unlink(self.__file.name)
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

    def append_rr(self, record):
        self.container.append_rr(record)

    def sort(self):
        """Sorts results"""
        self.container.sort()

    def diff(self, other):
        """
        Computes diff between two sorted results. Returns container that consists of difference.
        """
        filename = 'diff_' + str(self.id_range) + '_' + \
                   format_id(self.eid.id) + '-' + format_id(other.eid.id)
        diff_container = IteratorResult.from_filename(filename,
                                                      eid=other.eid,
                                                      id_range=other.id_range,
                                                      address=other.address,
                                                      tmp_dir=self.tmp_dir
                                                      )
        self.container.diff(other.container, diff_container.container)
        return diff_container

    @classmethod
    def merge(cls, results, tmp_dir):
        """
        Merges diffs and split result by node owner
        """
        ret = []

        if len(results) == 1:
            import shutil
            diff = results[0]
            filename = os.path.join(tmp_dir, "merge_" + mk_container_name(diff.id_range, diff.eid))
            shutil.copyfile(diff.filename, filename)
            ret.append(IteratorResult.load_filename(filename,
                                                    address=diff.address,
                                                    id_range=diff.id_range,
                                                    eid=diff.eid,
                                                    is_sorted=True,
                                                    tmp_dir=tmp_dir,
                                                    leave_file=True
                                                    ))
        elif len(results) != 0:
            vals = []
            for d in results:
                if d is None or len(d) == 0:
                    continue
                filename = os.path.join(tmp_dir, "merge_" + mk_container_name(d.id_range, d.eid))
                it = iter(d)
                vals.append((it.next(), it, IteratorResult.from_filename(filename,
                                                                         address=d.address,
                                                                         id_range=d.id_range,
                                                                         eid=d.eid,
                                                                         tmp_dir=tmp_dir,
                                                                         leave_file=True
                                                                         )))
            while len(vals):
                v_min = None
                for v, it, r in vals:
                    print "A"
                    if not v_min:
                        v_min = (v, it, r)
                        continue
                    if v.key < v_min[0].key or (v.key == v_min[0].key and v.timestamp > v_min[0].timestamp):
                        v_min = (v, it, r)

                v_min[2].append_rr(v_min[0])

                del_list = []
                for n, (v, it, r) in enumerate(vals):
                    print "B"
                    while v.key == v_min[0].key:
                        print "C"
                        try:
                            v = it.next()
                            vals[n] = (v, it, r)
                        except:
                            ret.append(r)
                            del_list.append(n)
                            break

                for d in del_list:
                    print "D"
                    del vals[d]
        return ret

    @classmethod
    def from_filename(cls, filename, tmp_dir="", **kwargs):
        """
        Creates iterator result from filename
        """
        if tmp_dir:
            filename = os.path.join(tmp_dir, filename)
        container_file = open(filename, 'w+')
        result = cls.from_fd(container_file.fileno(), tmp_dir=tmp_dir, filename=filename, **kwargs)
        result.__file = container_file  # Save it from python's gc
        return result

    @classmethod
    def load_filename(cls, filename, is_sorted=False, tmp_dir="", **kwargs):
        """
        Creates iterator result from filename
        """
        if tmp_dir:
            filename = os.path.join(tmp_dir, filename)
        if not os.path.exists(filename):
            return None
        container_file = open(filename, 'r+')
        container_file.seek(0, 2)
        result = cls.from_info(container_file.fileno(), is_sorted, container_file.tell(), tmp_dir=tmp_dir, filename=filename, **kwargs)
        result.__file = container_file  # Save it from python's gc
        return result

    @classmethod
    def from_info(cls, fd, is_sorted, position, **kwargs):
        result = cls(**kwargs)
        result.container = elliptics.IteratorResultContainer(fd, is_sorted, position)
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
              eid=elliptics.Id(IdRange.ID_MIN, 0),
              itype=elliptics.iterator_types.network,
              flags=elliptics.iterator_flags.key_range | elliptics.iterator_flags.ts_range,
              key_ranges=(IdRange(IdRange.ID_MIN, IdRange.ID_MAX),),
              timestamp_range=(Time.time_min().to_etime(), Time.time_max().to_etime()),
              tmp_dir='/var/tmp',
              address=None,
              leave_file=False,
              batch_size=1024
              ):
        assert itype == elliptics.iterator_types.network, "Only network iterator is supported for now"
        assert flags & elliptics.iterator_flags.data == 0, "Only metadata iterator is supported for now"
        assert len(key_ranges) > 0, "There should be at least one iteration range."

        try:
            id_start = min(r.start for r in key_ranges)
            id_stop = max(r.stop for r in key_ranges)
            id_range = IdRange(id_start, id_stop)
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
            last = 0

            for num, record in enumerate(records):
                # TODO: Here we can add throttling
                if record.status != 0:
                    raise RuntimeError("Iteration status check failed: {0}".format(record.status))
                result.append(record)
                last = num
                if last % batch_size == 0:
                    yield batch_size

            elapsed_time = records.elapsed_time()
            print (elapsed_time.tsec, elapsed_time.tnsec)
            yield last % batch_size
            yield result
        except Exception as e:
            self.log.error("Iteration failed: {0}".format(repr(e)))
            yield None

    @classmethod
    def iterate_with_stats(cls, node, eid, timestamp_range, key_ranges, tmp_dir, address, batch_size, stats, counters, leave_file=False):
        result = cls(node, eid.group_id).start(eid=eid,
                                               timestamp_range=timestamp_range,
                                               key_ranges=key_ranges,
                                               tmp_dir=tmp_dir,
                                               address=address,
                                               batch_size=batch_size,
                                               leave_file=leave_file
                                               )
        result_len = 0
        for it in result:
            if it is None:
                result = None
                break
            elif type(it) is IteratorResult:
                result = it
                break

            result_len += it
            for c in counters:
                stats.counter(c, it)

        return result, result_len
