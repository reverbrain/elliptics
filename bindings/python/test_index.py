#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys

sys.path.insert(0, "bindings/python/")
import elliptics

elog = elliptics.Logger("/dev/stderr", 0)
cfg = elliptics.Config()

node = elliptics.Node(elog, cfg)
node.add_remote("localhost", 1025)

s = elliptics.Session(node)
s.set_groups([1])

r = s.update_indexes("test_id", ["test_ind"], ["test_data"])
r.wait()
assert r.successful()

r = s.find_any_indexes(["test_ind"])
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].indexes[0][1] == "test_data"

r = s.find_all_indexes(["test_ind"])
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].indexes[0][1] == "test_data"

r = s.check_indexes("test_id")
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].data == "test_data"

z = s.find_any_indexes_raw([r.get()[0].index])
z.wait()
assert z.successful()
assert len(z.get()) >= 1
assert z.get()[0].indexes[0][1] == "test_data"

z = s.find_all_indexes_raw([r.get()[0].index])
z.wait()
assert z.successful()
assert len(z.get()) >= 1
assert z.get()[0].indexes[0][1] == "test_data"
