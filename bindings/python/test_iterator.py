#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "bindings/python/.libs/")
import elliptics
import binascii
from pprint import pprint

try:
	log = elliptics.Logger("/dev/stderr", 31)
	cfg = elliptics.Config()
	cfg.cookie = "0123456789012345678901234567890123456789"
	cfg.config.wait_timeout = 60

	n = elliptics.Node(log, cfg)
	
	n.add_remote("localhost", 1025)

	s = elliptics.Session(n)

	s.add_groups([2])
	
	id = elliptics.Id([1, 2, 3, 4], 2, 0)

	try:
		request = elliptics.IteratorRequest()
		request.key = [1, 2, 3, 4]
		request.end = [4, 3, 2, 1]
		print request
		iterator = s.start_iterator(id, request)
		print iterator
		for result in iterator:
			try:
				if result.status() != 0:
					print "error: ", result.status()
				else:
					print result.reply_data()
			except Exception as e:
				print "Invalid element"
	except Exception as e:
		print "Failed to start iterator:", e

except:
	print "Unexpected error:", sys.exc_info()
