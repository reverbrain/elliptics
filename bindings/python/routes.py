#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('bindings/python/.libs')
from libelliptics_python import *

def sid(id, count=6):
	ba = bytearray(id[0:count])
	ret = ''
	for i in range(count):
		ret += '%02x' % ba[i]

	return ret

def main():
	log = elliptics_log_file("/dev/stderr", 8)
	n = elliptics_node_python(log)

	group = 1

	n.add_groups([group])
	#remotes = [("squire", 1001), ("squire", 1010), ("squire", 1015)]
	remotes = [("localhost", 1025), ]
	for r in remotes:
		try:
			n.add_remote(r[0], r[1])
		except Exception as e:
			pass

	routes = n.get_routes()
	for r in routes:
		print sid(r[0].id, count=10), r[1]

if __name__ == '__main__':
	main()
