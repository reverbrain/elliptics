#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('bindings/python/')
import elliptics

from operator import itemgetter
from pprint import pprint

import argparse

def sid(id, count=6):
	ba = bytearray(id[0:count])
	ret = ''
	for i in range(count):
		ret += '%02x' % ba[i]

	return ret

def percentage(routes):
    groups = {}
    for r in routes:
        if not r[0].group_id in groups:
            groups[r[0].group_id] = []

        group = groups[r[0].group_id]
        group.append((sid(r[0].id, 16), r[1]))

    groups_percent = {}
    for g in groups.iterkeys():
        #print "routes for group %d" % g
        groups_percent[g] = {}

        host = groups[g][-1][1]
        groups[g].insert(0, ('0'*32, host))

        #host = groups[g][1][1]
        #groups[g].append(('f'*32, host))

        groups[g].sort(key=itemgetter(0))

        #for r in groups[g]:
            #print '    %s %s' % (r[0], r[1])

        host = groups[g][0][1]
        start = 0
        end = 0

        for r in groups[g]:
            #print 'host: %s, r[1]: %s' % (host, r[1])

            if r[1] == host:
                #print 'Skipping'
                continue

            end = int(r[0], 16)

            if not host in groups_percent[g]:
                groups_percent[g][host] = end-start
            else:
                groups_percent[g][host] += end-start

            #print 'groups_percent[%d][%s] = %x' % (g, host, groups_percent[g][host])
            host = r[1]
            start = end

        end = int('f'*32, 16)

        if not host in groups_percent[g]:
            groups_percent[g][host] = end-start
        else:
            groups_percent[g][host] += end-start

        #print 'groups_percent[%d][%s] = %x' % (g, host, groups_percent[g][host])

    for g in groups_percent:
        print 'Group: %d' % (g)
        for h in groups_percent[g]:
            print 'host %s %d%%' % (h, groups_percent[g][h] * 100 / int('f'*32, 16))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Get remote route table and print its statistics.')
	parser.add_argument('remotes', metavar='N', type=str, nargs='+',
		help='Remote nodes to connect and grab route tables. Format: addr:port:family, where family = 2 for ipv4 and 10 for ipv6')
	parser.add_argument('--percentage', dest='percentage', action='store_true',
		help='if present, dump parts of DHT ring each node occupies (in percents)')
	parser.add_argument('--log', default='/dev/stdout', help='log file')
	parser.add_argument('--log-level', type=int, default=elliptics.log_level.error,
		help='log level: %d-%d' % (elliptics.log_level.data, elliptics.log_level.debug))

	args = parser.parse_args()
	if len(args.remotes) == 0:
		args.remotes = "localhost:1025:2"

	log = elliptics.Logger(args.log, args.log_level)
	n = elliptics.Node(log)
	s = elliptics.Session(n)

	try:
		for r in args.remotes:
			spl = r.split(":")
			n.add_remote(addr=spl[0], port=int(spl[1]), family=int(spl[2]))
	except Exception as e:
		print e
		pass

	routes = s.get_routes()
	if args.percentage:
		percentage(routes)
	else:
		for r in sorted(routes, key=lambda eid_tuple: eid_tuple[0].id):
			print r[0].group_id, sid(r[0].id), r[1]
