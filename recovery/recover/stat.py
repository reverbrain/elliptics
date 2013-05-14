from datetime import datetime
from itertools import chain

__doc__ = \
    """
    Stats for humans (c)
    Simple and Python-ish interface to stats.
    Currently we support counters and time measurements.
    """


def format_kv(k, v):
    return '{0:<40}{1:>40}'.format(k + ':', str(v))


class ResultCounter(object):
    __slots__ = ('name', 'total', 'success', 'failures')
    __doc__ = \
        """
        XXX:
        """

    def __init__(self, name, success=0, failures=0):
        self.name = name
        self.success = success
        self.failures = failures
        self.total = success + failures

    def __iadd__(self, other):
        self.success += other
        self.total += other
        return self

    def __isub__(self, other):
        self.total += other
        self.failures += other
        return self

    def __str__(self):
        result = []
        for cntr in self.__slots__:
            if cntr != 'name':
                result.append(format_kv(self.name + '_' + cntr, getattr(self, cntr)))
        return "\n".join(result)


class DurationTimer(object):
    __slots__ = ('name', 'times',)
    __doc__ = \
        """
        XXX:
        """

    def __init__(self, name):
        self.name = name
        self.times = []

    def __call__(self, name=None):
        self.times.append((name, datetime.now()))

    def __str__(self):
        if not self.times:
            return ""

        def construct_line(times):
            measure_name, measure_time = times
            result = str(self.name) + "_" + str(measure_name)
            return format_kv(result, measure_time)

        result = []
        start, stop = self.times[0], self.times[-1]
        result.append(construct_line(start))
        for begin, end in zip(self.times, self.times[1:]):
            name = str(begin[0]) + "-" + str(end[0])
            time = end[1] - begin[1]
            result.append(construct_line((name, time)))
        if start != stop:
            result.append(construct_line(stop))
        return "\n".join(result)


class Container(object):
    __doc__ = \
        """
        XXX:
        """

    def __init__(self, klass, *args, **kwargs):
        self.__klass = klass
        self.__args = args
        self.__kwargs = kwargs
        self.__container = dict()

    def __getattr__(self, item):
        if item not in self.__container:
            self.__container[item] = self.__klass(name=item, *self.__args, **self.__kwargs)
        return self.__container[item]

    def __iter__(self):
        return self.__container.iteritems()


class Stats(object):
    __doc__ = \
        """
        XXX:
        """

    def __init__(self, name=None):
        self.name = name
        self.counter = Container(ResultCounter)
        self.timer = Container(DurationTimer)
        self.__sub_stats = Container(Stats)

    def __str__(self):
        result = []
        result.append("{0:=^80}".format(" " + str(self.name) + " "))
        for _, v in chain(sorted(self.counter), sorted(self.timer), sorted(self.__sub_stats)):
            result.append(str(v))
        return "\n".join(result)

    def __getitem__(self, item):
        return getattr(self.__sub_stats, str(item))
