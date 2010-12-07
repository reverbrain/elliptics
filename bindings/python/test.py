#!/usr/bin/python
# -*- coding: utf-8 -*-

from libelliptics_python import *
from array import *
import sys

try:
	log = elliptics_log_file("/dev/stderr", 15)
	n = elliptics_node_python(log)

	n.add_remote("localhost", 1025)

	id = elliptics_id()
	id.id = [1, 2, 3, 4]
	id.group_id = 2
	id.version = 0

	n.write_data(id, '1234567890qwertyuio')

	s = n.read_data(id, 0)
	print s
except:
	print "Unexpected error:", sys.exc_info()[0]
