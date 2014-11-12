#!/usr/bin/python
# -*- coding: utf-8 -*-

# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

import random

rnd = random.randint(0, 999999999)
test_id = "test_id_" + str(rnd)
test_ind = "test_ind_" + str(rnd)
test_data = "test_data_" + str(rnd)

import elliptics

elog = elliptics.Logger("/dev/stderr", 0)
cfg = elliptics.Config()

node = elliptics.Node(elog, cfg)
node.add_remotes("localhost:1025:2")

s = elliptics.Session(node)
s.set_groups([1])

r = s.set_indexes(elliptics.Id(test_id), [test_ind], [test_data])
r.wait()
assert r.successful()

r = s.find_any_indexes([test_ind])
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].indexes[0].data == test_data

r = s.find_all_indexes([test_ind])
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].indexes[0].data == test_data

r = s.list_indexes(elliptics.Id(test_id))
r.wait()
assert r.successful()
assert len(r.get()) >= 1
assert r.get()[0].data == test_data


z = s.find_any_indexes_raw([elliptics.Id(test_ind)])
z.wait()
assert z.successful()
assert len(z.get()) >= 1
assert z.get()[0].indexes[0].data == test_data

z = s.find_all_indexes_raw([elliptics.Id(test_ind)])
z.wait()
assert z.successful()
assert len(z.get()) >= 1
assert z.get()[0].indexes[0].data == test_data
