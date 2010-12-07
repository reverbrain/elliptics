#!/usr/bin/python
# -*- coding: utf-8 -*-

from libelliptics_python import *
from array import *
import sys

try:
	log = elliptics_log_file("/dev/stderr", 15)
	n = elliptics_node_python(log)

	n.add_groups([1,2,3])
	n.add_remote("localhost", 1025)

	id = elliptics_id()
	id.id = [1, 2, 3, 4]
	id.group_id = 2
	id.version = 0

	# write data by ID into specified group (# 2)
	# read data from the same group (# 2)
	n.write_data(id, '1234567890qwertyuio')
	s = n.read_data(id, 0)
	print s

	# write data into all 3 groups specified in add_groups() call.
	# read data from the first available group
	n.write_data("test.txt", '1234567890qwertyuio')
	s = n.read_data("test.txt", 0)
	print s
except:
	print "Unexpected error:", sys.exc_info()[0]
