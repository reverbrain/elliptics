#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append("bindings/python")
from elliptics import *

from time import time, ctime

def add_remotes(n):
	addresses = [("localhost", 1025),
			("localhost", 1026),
			("172.16.136.1", 1025),
			("172.16.136.1", 1026),
			]
	failed = 0

	for addr in addresses:
		try:
			n.add_remote(addr[0], addr[1])
		except:
			failed += 1
			pass

	if failed == len(addresses):
		raise NameError("Can not add remote nodes")

def write(n, id, aflags, groups):
	remote_offset = 0
	ioflags = 0

	n.write_data(id, "time: " + ctime(time()), remote_offset, aflags, ioflags)
	n.write_metadata(id, "remote id", groups, aflags)


def main():
	try:
		log = Logger("/dev/stderr", 2)
		n = Node(log)

		groups = [1, 2, 3]

		n.add_groups(groups)
		add_remotes(n)

		id = Id([1, 2, 3, 4], 3, 0)

		aflags = 16 # no locks

		write(n, id, aflags, groups)
		ret = n.prepare_latest(id, aflags, groups)

		print "Groups returned:", ret

	except Exception as e:
		print "Exception:", e

if __name__ == "__main__":
	main()
