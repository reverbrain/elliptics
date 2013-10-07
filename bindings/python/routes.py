#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.append('bindings/python/')
import elliptics

import argparse


def percentage(routes):
    percentages = routes.percentages()
    for g in percentages:
        print 'Group: {0}'.format(g)
        for h in percentages[g]:
            print 'host {0} {1:.2f}'.format(h, percentages[g][h])

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
            n.add_remote(r)
    except Exception as e:
        print e
        pass

    routes = s.get_routes()
    if args.percentage:
        percentage(routes)
    else:
        print routes
