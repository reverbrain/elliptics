#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, "/usr/lib/")
sys.path.insert(0, "./.libs/")
sys.path.insert(0, "bindings/python/.libs/")
from libelliptics_python import *

import struct, binascii, os

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
		self.eid = elliptics_id([int(binascii.hexlify(x), 16) for x in self.id], 0, 0)
	
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

class merge:
	def __init__(self, remotes=[], group=0, log='/dev/stdout', mask=8, own=''):
		self.log = elliptics_log_file(log, mask)
		self.n = elliptics_node_python(self.log)

		for r in remotes:
			try:
				self.n.add_remote(r[0], r[1])
			except:
				pass

		self.own = own
		self.routes = []
		for r in self.n.get_routes():
			if r[0].group_id == group:
				self.routes.append(r)

		self.routes.sort(key = lambda x: x[0].id)

	def eid_more(self, e1, e2):
		return e1.id >= e2.id

	def destination(self, eid):
		ret = self.routes[-1]
		for r in self.routes:
			if self.eid_more(eid, r[0]):
				ret = r
			else:
				break

		return ret

	def sid(self, eid, count=6):
		ba = bytearray(eid.id[0:count])
		ret = ''
		for i in range(count):
			ret += '%02x' % ba[i]

		return ret

	def merge(self, inpath='', outpath=''):
		input = blob(inpath)

		outb = {}
		for r in self.routes:
			if r[1] != self.own:
				if not r[1] in outb:
					outb[r[1]] = blob(outpath + '-' + r[1], 'ab')

		for eid in input.iterate(want_removed=False):
			d = self.destination(eid)
			if d[1] != self.own:
				b = outb[d[1]]

				input.read_data()

				pos = b.dataf.tell()
				old_pos = input.position
				input.position = pos

				idata, data = input.get_data()

				b.index.write(idata)
				b.dataf.write(idata)
				b.dataf.write(input.data[blob.index_size:])

				input.position = old_pos
				input.mark_removed()
				input.update()

				#print self.sid(eid), self.sid(d[0]), outpath + '-' + d[1]

if __name__ == '__main__':
	# list of tuples of remote addresses to connect and grab route table
	remotes = [('elisto19f.dev', 1025)]

	# when doing merge, only select addresses from this group
	want_group = 8

	# when doing merge, do NOT get IDs which belong to this address
	# it must be IPv4 address:port
	except_addr = '95.108.228.167:1025'

	# Path to blob to get objects from. Index file must be near with .index suffix
	inpath='/opt/elliptics/eblob.2/data.0'

	# output path - real output files will have '-addr:port' suffix added
	# you may want to copy them to appropriate elliptics nodes
	# Then on remote node you should rename this file to needed name
	# (if you have data.3 file in elliptics blob dir, this may be data.4)
	# and then restart ioserv, it will catch up new blobs and start serving requests
	# Be careful with different columns - blobs with names like 'data-1'
	# This tool does not know what column this data has, it will create output
	# files with this prefix only and described above suffix
	outpath='/tmp/blob.test'


	m = merge(remotes=remotes, group=want_group, own=except_addr)
	m.merge(inpath=inpath, outpath=outpath)
