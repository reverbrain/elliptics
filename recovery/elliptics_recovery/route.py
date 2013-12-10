# =============================================================================
# 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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

"""
Route management routines

Vanilla elliptics python bindings are too C'ish.
We need better abstractions.
"""

from socket import getaddrinfo, SOL_TCP, AF_INET6, AF_INET
from itertools import groupby, izip
from operator import attrgetter, itemgetter

from .utils.misc import logged_class
from .range import IdRange, RecoveryRange, AddressRanges

import sys
sys.path.insert(0, "bindings/python/") # XXX
import elliptics
from elliptics.route import RouteList

@logged_class
class RouteList(RouteList):
    """
    Route list that sorts entries by key and also merges
    keys that belongs to the same node.
    """
    @classmethod
    def from_session(cls, session):
        """
        Create RouteList from elliptics session.

        It slightly mangles route list by explicitly inserting start and end of
        hash-ring and also merging adj. routes for the same into one.
        """
        return cls(session.get_routes().routes)

    def get_ranges_by_address(self, address):
        ranges = []
        group_id = self.get_address_eid(address).group_id
        keys = dict()
        include = False
        for route in self.routes:
            keys[route.address.group_id] = (route.key, route.address)
            if route.address.group_id == group_id:
                include = route.address == address

        for i, route in enumerate(self.routes):
            keys[route.address.group_id] = (route.key, route.address)
            if i < len(self.routes) - 1:
                next_route = self.routes[i + 1].key

            if route.address.group_id != group_id and not include:
                continue

            if route.address == address:
                include = True
                ranges.append(RecoveryRange(IdRange(route.key, next_route), keys.copy()))
            elif route.address.group_id == group_id:
                include = False
            elif include:
                ranges.append(RecoveryRange(IdRange(route.key, next_route), keys.copy()))

        return ranges

    def get_local_ranges_by_address(self, address):
        ranges = self.get_ranges_by_address(address)
        result = dict((address,
                       AddressRanges(address=address,
                                     eid=self.get_address_eid(address),
                                     id_ranges=[])) for address in self.addresses())

        for r in ranges:
            for group_id in r.address:
                address = r.address[group_id][1]
                assert result[address].address.group_id == group_id
                result[address].id_ranges.append(r.id_range)

        return [v for v in result.values() if len(v.id_ranges)]
