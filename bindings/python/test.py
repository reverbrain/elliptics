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
		print n.lookup_addr("qwerty.xml", group)
	except:
		print "Failed to lookup in group ", group

	id = elliptics_id([1, 2, 3, 4], 2, 0)

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	try:
		data = '1234567890qwertyuio'
		n.write_data(id, data, 0, 0, 0)
		print "WRITE:", data
	except:
		print "Failed to write data by id"

	try:
		s = n.read_data(id, 0, 0, 0, 0)
		print " READ:", s
	except:
		print "Failed to read data by id"

	# write data into all 3 groups specified in add_groups() call.
	# read data from the first available group
	try:
		key = "test.txt"
		data = '1234567890qwertyuio'
		n.write_data(key, data, 0, 0, 0, 0)
		print "WRITE:", key, ":", data
	except:
		print "Failed to write data by string"

	try:
		key = "test.txt"
		s = n.read_data("test.txt", 0, 0, 0, 0, 0)
		print " READ:", key, ":", s
	except:
		print "Failed to read data by string"

	print n.read_latest("2.xml", 0, 0, 0, 0, 0);

except:
	print "Unexpected error:", sys.exc_info()
