#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

sys.path.insert(0, "bindings/python/")
import elliptics

try:
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
    request.flags = elliptics.iterator_flags.key_range|elliptics.iterator_flags.ts_range
    request.key_begin = [0] * 64
    request.key_end = [255] * 64
    request.time_begin = elliptics.Time(0, 0)
    request.time_end = elliptics.Time(2**64-1, 2**64-1)

    try:
        eid = elliptics.Id([0] * 64, 2, 0)
        iterator = s.start_iterator(eid, request)
        for result in iterator:
            try:
                if result.status != 0:
                    print "error: {0}".format(result.status)
                else:
                    print "key: {0}, flags: {1}, ts: {2}/{3}, data: {4}".format(result.key,
                            result.user_flags, result.timestamp.tsec, result.timestamp.tnsec,
                            result.response_data())
            except Exception as e:
                print "Invalid element: {0}".format(e)
    except Exception as e:
        print "Iteration failed: {0}:".format(e)

except Exception:
    print "Unexpected error:", sys.exc_info()
