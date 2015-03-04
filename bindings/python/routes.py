#!/usr/bin/python
# -*- coding: utf-8 -*-

# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

import elliptics
import argparse


def percentage(routes):
    percentages = routes.percentages()
    for group in percentages:
        print 'Group {0}:'.format(group)
        for host in percentages[group]:
            for backend_id in percentages[group][host]:
                print '\thost {0}/{1}\t{2:.2f}'.format(host, backend_id, percentages[group][host][backend_id])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get remote route table and print its statistics.')
    parser.add_argument('remotes', metavar='N', type=str, nargs='+',
        help='Remote nodes to connect and grab route tables. Format: addr:port:family, where family = 2 for ipv4 and 10 for ipv6')
    parser.add_argument('--percentage', dest='percentage', action='store_true',
        help='if present, dump parts of DHT ring each node occupies (in percents)')
    parser.add_argument('--log', default='/dev/stdout', help='log file')
    parser.add_argument('--log-level', type=int, default=elliptics.log_level.error,
        help='log level: %d-%d' % (elliptics.log_level.error, elliptics.log_level.debug))

    args = parser.parse_args()
    if len(args.remotes) == 0:
        args.remotes = "localhost:1025:2"

    log = elliptics.Logger(args.log, args.log_level)
    n = elliptics.Node(log)
    s = elliptics.Session(n)

    try:
        n.add_remotes(args.remotes)
    except Exception as e:
        print e
        pass

    if args.percentage:
        percentage(s.routes)
    else:
        print s.routes
