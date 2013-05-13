#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

sys.path.insert(0, "bindings/python/")
import elliptics

if __name__ == '__main__':
    log = elliptics.Logger("/dev/stderr", 1)
    cfg = elliptics.Config()
    cfg.cookie = "0123456789012345678901234567890123456789"
    cfg.config.wait_timeout = 60

    n = elliptics.Node(log, cfg)
    n.add_remote("localhost", 1025)

    s = elliptics.Session(n)
    s.add_groups([2])

    request = elliptics.IteratorRequest()
    request.action = elliptics.iterator_actions.start
    request.itype = elliptics.iterator_types.network
    request.flags = elliptics.iterator_flags.key_range \
            | elliptics.iterator_flags.ts_range | elliptics.iterator_flags.data
    request.key_begin = [0] * 64
    request.key_end = [255] * 64
    request.time_begin = elliptics.Time(0, 0)
    request.time_end = elliptics.Time(2**64-1, 2**64-1)

    eid = elliptics.Id([0] * 64, 2, 0)
    iterator = s.start_iterator(eid, request)
    for i, result in enumerate(iterator):
        if result.status != 0:
            raise AssertionError("Wrong status: {0}".format(result.status))

        print "key: {0}, flags: {1}, ts: {2}/{3}, data: {4}".format(
			result.response.key,
			result.response.user_flags,
			result.response.timestamp.tsec, result.response.timestamp.tnsec,
			result.response_data())

        # Test flow control
        if i % 10 == 0:
            print "Pause iterator"
            pause = elliptics.IteratorRequest()
            pause.id = result.id
            pause.action = elliptics.iterator_actions.pause
            pause_it = s.start_iterator(eid, pause)
            print "Continue iterator"
            cont = elliptics.IteratorRequest()
            cont.id = result.id
            cont.action = elliptics.iterator_actions.cont
            cont_it = s.start_iterator(eid, cont)
