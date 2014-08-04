#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import glob
import os
import re

sys.path.insert(0, "/usr/lib/")
sys.path.insert(0, "/lib/python2.6/site-packages/")
from libelliptics_python import *
import eblob

class merge:
	def __init__(self, remotes=[], group=0, log='/dev/stdout', mask=8, own=''):
		self.log = elliptics_log_file(log, mask)
		self.n = elliptics_node_python(self.log)

		self.n.add_remotes(remotes)

		self.own_group = group
		self.own = own
		self.routes = []
		for r in self.n.get_routes():
			if r[0].group_id == group:
				self.routes.append(r)

		if len(self.routes) == 0:
			raise NameError("Route table for group " + str(group) + " is empty")

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

	def merge(self, inpath='', outpath=''):
		input = eblob.blob(inpath)

		outb = {}
		for r in self.routes:
			if r[1] != self.own:
				if not r[1] in outb:
					outb[r[1]] = eblob.blob(outpath + '-' + r[1], data_mode='ab', index_mode='ab')

		for id in input.iterate(want_removed=False):
			d = self.destination(elliptics_id(list(bytearray(id)), self.own_group, -1))

			if d[1] != self.own:
				b = outb[d[1]]

				input.read_data()

				pos = b.dataf.tell()
				old_pos = input.position
				input.position = pos

				idata, data = input.get_data()

				b.index.write(idata)
				b.dataf.write(idata)
				b.dataf.write(input.data[eblob.blob.index_size:])

				input.position = old_pos
				input.mark_removed()
				input.update()

if __name__ == '__main__':
	# list of tuples of remote addresses to connect and grab route table
	remotes = ['elisto19f.dev:1025:2')]

	# when doing merge, only select addresses from this group
	want_group = 1

	# when doing merge, do NOT get IDs which belong to this address
	# it must be IPv4 address:port
	# when setting it to obscure string, we force merge process to spread all IDs
	# so that no single key will belong to the host of the input blob
	# localhost is kind of such 'obscure string' - if remote nodes are not on the localhost,
	# then there is no way we may have localaddr in route table (remember, this address
	# is announced when node joins network, so remote nodes connect to it)
	except_addr = '127.0.0.1:1025'

	# Path to blob to get objects from. Index file must be near with .index suffix
	indir='/srv/data'

	# output path - real output files will have '-addr:port' suffix added
	# you may want to copy them to appropriate elliptics nodes
	# Then on remote node you should rename this file to needed name
	# (if you have data.3 file in elliptics blob dir, this may be data.4)
	# and then restart ioserv, it will catch up new blobs and start serving requests
	outdir='/srv/data/new'

	# please note that after merge process completed you should remove sorted index
	# for appropriate blob, since it is not updated during merge iteration process,
	# so local node will continue to 'think' that some records are not removed
	# reading will fail, since it checks data and index headers,
	# but still it is a performance issue

	# maximum output blob size in bytes
	blobsize = 40*1024*1024*1024

	for blobtype in ['data', 'data-1']:
		# list of blobtype blobs
		inlist = map(os.path.basename, glob.glob(indir + '/' + blobtype + '.*'))
		# filter .index, data.stat, etc files
		inlist = filter(lambda x: re.match('^data(-[0-9]+)?\.[0-9]+$', x), inlist)
		# sort by blob id
		inlist = sorted(inlist, key=lambda x: int(x.rsplit('.', 1)[1]))

		# output blob id
		outblobnum = 0
		for inblob in inlist:
			inpath = indir + '/' + inblob

			while True:
				# output path for blob
				outpath = outdir + '/' + blobtype + '.' + str(outblobnum)
				# list of already merged blogs
				outlist = glob.glob(outpath + '-*')
				# filter .index files
				outlist = filter(lambda x: not x.endswith('.index'), outlist)

				# ok if blobs not found or all blob sizes less than blobsize
				if len(outlist) < 1 or max(map(os.path.getsize, outlist)) < blobsize:
					break

				outblobnum += 1

			try:
				print "Doing merge from %s to %s" % (inpath, outpath)
				m = merge(remotes=remotes, group=want_group, own=except_addr)
				m.merge(inpath=inpath, outpath=outpath)
			except NameError as e:
				del m
				print "Processes completed:", e
				print "Please remove %s now and restart elliptics (it will regenerate sorted index if needed)\n" %\
						(inpath + '.index.sorted')
