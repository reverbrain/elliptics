#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "/usr/lib/")
sys.path.insert(0, "./.libs/")
sys.path.insert(0, "bindings/python/.libs/")
from libelliptics_python import *

import struct, os

class blob:
	format = '<64sQQQQ'
	index_size = struct.calcsize(format)

	FLAGS_REMOVED = 1

	def __init__(self, path, mode='r+b'):
		self.dataf = open(path, mode)
		self.index = open(path + '.index', mode)

		self.position = 0
		self.id = ''
		self.data_size = 0
		self.disk_size = 0
		self.flags = 0
		self.data = ''

	def read_index(self):
		idata = self.index.read(self.index_size)
		if len(idata) != self.index_size:
			raise NameError('Finished index')

		self.id, self.flags, self.data_size, self.disk_size, self.position = struct.unpack(self.format, idata)
		self.eid = elliptics_id(list(bytearray(self.id)), 0, 0)
	
	def removed(self):
		return self.flags & self.FLAGS_REMOVED

	def mark_removed(self):
		self.flags |= self.FLAGS_REMOVED

	def read_data(self):
		self.dataf.seek(self.position)
		self.data = self.dataf.read(self.disk_size)

		if len(self.data) != self.disk_size:
			raise NameError('Finished data')

	def update(self):
		idata = struct.pack(self.format, self.id, self.flags, self.data_size, self.disk_size, self.position)
		self.index.seek(-self.index_size, os.SEEK_CUR)
		self.index.write(idata)

		self.dataf.seek(self.position)
		self.dataf.write(idata)

	def get_data(self):
		idata = struct.pack(self.format, self.id, self.flags, self.data_size, self.disk_size, self.position)
		return idata, self.data

	def iterate(self, want_removed=False):
		while True:
			self.read_index()
			if want_removed:
				yield self.eid

			if not self.removed():
				yield self.eid

class remover:
	def sid(self, eid, count=6):
		ba = bytearray(eid.id[0:count])
		ret = ''
		for i in range(count):
			ret += '%02x' % ba[i]

		return ret

	def __init__(self, remotes=[], groups=[], log='/dev/stdout', mask=8, path=''):
		self.log = elliptics_log_file(log, mask)
		self.n = elliptics_node_python(self.log)

		self.n.add_groups(groups)
		for r in remotes:
			try:
				self.n.add_remote(r[0], r[1])
			except:
				pass
		if len(self.n.get_routes()) == 0:
			raise NameError("Route table for group " + str(group) + " is empty")

		b = blob(path)
		for eid in b.iterate(want_removed=True):
			if b.removed():
				for g in groups:
					eid.group_id = g
					self.n.remove(eid, 0)

				print self.sid(eid, count=64)


if __name__ == '__main__':

	# this script runs over index for given blob, finds all removed entries and removes them from the storage

	# list of tuples of remote addresses to connect and grab route table
	remotes = [('elisto19f.dev', 1025)]

	# these groups 
	groups = [1, 2, 3]

	# Path to blob to get objects from. Index file must be near with .index suffix
	inpath='/opt/elliptics/eblob.2/data.0'

	try:
		remover(remotes=remotes, groups=groups, path=inpath)
	except NameError as e:
		print "Completed:", e
