#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "/usr/lib/")
sys.path.insert(0, "./.libs/")
from libelliptics_python import *
import binascii
from pprint import pprint

try:
	log = elliptics_log_file("/dev/stderr", 8)
	n = elliptics_node_python(log)

	n.add_groups([1,2,3])
	n.add_remote("localhost", 1025)

	group = 1
	try:
		obj = "qwerty.xml"
		addr = n.lookup_addr(obj, group)
		print "object", obj, "should live at", addr, "in group", group
	except Exception as e:
		print "Failed to lookup in group", group, ":", e

	id = elliptics_id([1, 2, 3, 4], 1, 0)

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	try:
		data = '1234567890qwertyuio'
		n.write_data(id, data, 0, 0, 0)
		print "WRITE:", data
		n.write_metadata(id, "", [1], 0)
		print "Write metadata"
	except Exception as e:
		print "Failed to write data by id:", e

	try:
		s = n.read_data(id, 0, 0, 0, 0)
		print " READ:", s
	except Exception as e:
		print "Failed to read data by id:", e

	id.type = -1
	n.remove(id, 0)
	try:
		s = n.read_data(id, 0, 0, 0, 0)
		print " READ:", s
	except Exception as e:
		print "Failed to read data by id:", e

	# write data into all 3 groups specified in add_groups() call.
	# read data from the first available group
	try:
		key = "test.txt"
		data = '1234567890qwertyuio'
		n.write_data(key, data, 0, 0, 0, 0)
		print "WRITE:", key, ":", data
		n.write_metadata(key, 0)
		print "Write metadata"
	except Exception as e:
		print "Failed to write data by string:", e

	try:
		key = "test.txt"
		s = n.read_data("test.txt", 0, 0, 0, 0, 0)
		print " READ:", key, ":", s
	except Exception as e:
		print "Failed to read data by string:", e

	try:
		print n.read_latest("test.txt", 0, 0, 0, 0, 0);
	except Exception as e:
		print "Failed to read latest data by string:", e

	# bulk read of keys by name
	try:
		files =  n.bulk_read(["test1", "test2", "test3", "test4", "test5"], 1, 0)
		for f in files:
			print binascii.hexlify(f[:6]), ":", f[68:]
	except Exception as e:
		print "Failed to read bulk:", e

	routes = n.get_routes()
	for route in routes:
		print route[0].group_id, route[0].id, route[1]

	print "Requesting stat_log"
	pprint(n.stat_log())

except:
	print "Unexpected error:", sys.exc_info()
