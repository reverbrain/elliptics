#!/usr/bin/python
# -*- coding: utf-8 -*-

from libelliptics_python import *
import sys

try:
	log = elliptics_log_file("/dev/stderr", 8)
	n = elliptics_node_python(log)

	n.add_groups([1,2,3])
	n.add_remote("localhost", 1025)

	group = 5
	try:
		obj = "qwerty.xml"
		addr = n.lookup_addr(obj, group)
		print "object", obj, "should live at", addr, "in group", group
	except Exception as e:
		print "Failed to lookup in group", group, ":", e

	id = elliptics_id([1, 2, 3, 4], 2, 0)

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	try:
		data = '1234567890qwertyuio'
		n.write_data(id, data, 0, 0, 0)
		print "WRITE:", data
	except Exception as e:
		print "Failed to write data by id:", e

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
	except Exception as e:
		print "Failed to write data by string:", e

	try:
		key = "test.txt"
		s = n.read_data("test.txt", 0, 0, 0, 0, 0)
		print " READ:", key, ":", s
	except Exception as e:
		print "Failed to read data by string:", e

	print n.read_latest("2.xml", 0, 0, 0, 0, 0);

except:
	print "Unexpected error:", sys.exc_info()
