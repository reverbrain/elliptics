#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from libelliptics_python import *
import eblob

class remover:
	def __init__(self, remotes=[], groups=[], log='/dev/stdout', mask=8, path=''):
		self.log = elliptics_log_file(log, mask)
		self.n = elliptics_node_python(self.log)

		self.n.add_groups(groups)
		self.n.add_remotes(remotes)
		if len(self.n.get_routes()) == 0:
			raise NameError("Route table for group " + str(group) + " is empty")

		b = eblob.blob(path)
		for id in b.iterate(want_removed=True):
			if b.removed():
				for g in groups:
					eid = elliptics_id(list(bytearray(id)), g, -1)
					self.n.remove(eid, 0)

				print "%s: flags: 0x%x, position: %d, data_size: %d" % \
					(b.sid(count=64), b.flags, b.position, b.data_size)


if __name__ == '__main__':
	# this script runs over index for given blob, finds all removed entries and removes them from the storage

	# list of tuples of remote addresses to connect and grab route table
	remotes = [('elisto19f.dev:1025:2')]

	# these groups
	groups = [1, 2, 3]

	# Path to blob to get objects from. Index file must be near with .index suffix
	inpath='/opt/elliptics/eblob.2/data.0'

	try:
		remover(remotes=remotes, groups=groups, path=inpath)
	except NameError as e:
		print "Completed:", e
