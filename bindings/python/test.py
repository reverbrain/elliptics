#!/usr/bin/python
# -*- coding: utf-8 -*-

from libelliptics_python import *
import sys

try:
	log = elliptics_log_file("/dev/stderr", 15)
	n = elliptics_node_python(log)

	n.add_groups([1,2,3])
	n.add_remote("localhost", 1025)

	print n.lookup_addr("qwerty.xml", 5)

	id = elliptics_id([1, 2, 3, 4], 2)

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	try:
		n.write_data(id, '1234567890qwertyuio')
	except:
		print "Failed to write data by id"

	try:
		s = n.read_data(id, 0)
		print s
	except:
		print "Failed to read data by id"

	# write data into all 3 groups specified in add_groups() call.
	# read data from the first available group
	try:
		n.write_data("test.txt", '1234567890qwertyuio')
	except:
		print "Failed to write data by string"

	try:
		s = n.read_data("test.txt", 0)
		print s
	except:
		print "Failed to read data by string"

except:
	print "Unexpected error:", sys.exc_info()
