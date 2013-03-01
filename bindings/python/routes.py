#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('bindings/python/')
import elliptics

def sid(id, count=6):
	ba = bytearray(id[0:count])
	ret = ''
	for i in range(count):
		ret += '%02x' % ba[i]

	return ret

def main():
	log = elliptics.Logger("/dev/stderr", 1)
	n = elliptics.Node(log)

	s = elliptics.Session(n)
	s.add_groups([1])

	remotes = [("localhost", 1025), ]
	for r in remotes:
		try:
			n.add_remote(r[0], r[1])
		except Exception as e:
			pass

	routes = s.get_routes()
	for r in sorted(routes, key=lambda eid_tuple: eid_tuple[0].id):
		print r[0].group_id, sid(r[0].id), r[1]

if __name__ == '__main__':
	main()
