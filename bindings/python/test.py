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

import sys
import elliptics
import binascii
from pprint import pprint

try:
	log = elliptics.Logger("/dev/stderr", 31)
	cfg = elliptics.Config()
	cfg.cookie = "0123456789012345678901234567890123456789"
	cfg.config.wait_timeout = 60

	n = elliptics.Node(log, cfg)

	n.add_remotes("localhost:1025:2")

	s = elliptics.Session(n)

	s.add_groups([1,2,3])

	group = 1
	try:
		obj = "qwerty.xml"
		addr = s.lookup_address(obj, group)
		print "object", obj, "should live at", addr, "in group", group
	except Exception as e:
		print "Failed to lookup in group", group, ":", e

	id = elliptics.Id([1, 2, 3, 4], 1)

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	try:
		data = '1234567890qwertyuio'
		s.write_data(id, data, 0).wait()
		print "WRITE:", data
	except Exception as e:
		print "Failed to write data by id:", e

	try:
		res = s.read_data(id, 0, 0).get()[0]
		print " READ:", res.data
	except Exception as e:
		print "Failed to read data by id:", e

	id.type = -1
	s.remove(id)
	try:
		res = s.read_data(id, 0, 0).get()[0]
		print " READ:", res.data
	except Exception as e:
		print "Failed to read data by id:", e

	# write data into all 3 groups specified in add_groups() call.
	# read data from the first available group
	try:
		key = "test.txt"
		data = '1234567890qwertyuio'
		s.write_data(key, data, 0).wait()
		print "WRITE:", key, ":", data
	except Exception as e:
		print "Failed to write data by string:", e

	try:
		key = "test.txt"
		res = s.read_data(key, 0, 0).get()[0]
		print " READ:", key, ":", res.data
	except Exception as e:
		print "Failed to read data by string:", e

	try:
		print s.read_latest("test.txt", 0, 0).get()[0].data;
	except Exception as e:
		print "Failed to read latest data by string:", e

	# bulk read of keys by name
	try:
		files =  s.bulk_read(["test1", "test2", "test3", "test4", "test5"])
		for f in files:
			print binascii.hexlify(f[:6]), ":", f[68:]
	except Exception as e:
		print "Failed to read bulk:", e

	for route in s.routes:
		print route[0].group_id, route[0], route[1]

except:
	print "Unexpected error:", sys.exc_info()
