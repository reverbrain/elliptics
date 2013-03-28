#!/usr/bin/python
# -*- coding: utf-8 -*-

import random
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
    request.itype = 2                # Network
    request.flags = 1                # With data
    request.begin = [0]*8
    request.end = [255]*8

    try:
        eid = elliptics.Id([random.randrange(0, 256)] * 8, 2, 0)
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
