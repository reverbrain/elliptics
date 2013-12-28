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

from socket import getaddrinfo, SOL_TCP, AF_INET6, AF_INET
from itertools import groupby, izip
from operator import attrgetter, itemgetter
from elliptics.core import Id
from elliptics.log import logged_class


@logged_class
class Address(object):
    """
    Address wrapper. Resolves host names into IP addresses.
    """
    # Allowed families, 0 means any
    ALLOWED_FAMILIES = (0, AF_INET, AF_INET6)

    def __init__(self, host, port=None, family=0, group_id=0):
        """
        Initializes Address from host, port and optional family, group_id\n
        address = elliptics.Address(host='host.com', port=1025,
                                    family=2, group_id=0)
        """
        if family not in self.ALLOWED_FAMILIES:
            raise ValueError("Family '{0}' is not in {1}"
                             .format(family, self.ALLOWED_FAMILIES))

        gai = getaddrinfo(host, port, family, 0, SOL_TCP)
        if len(gai) > 1:
            self.log.warning("More than one IP found"
                             "for: {0}. Using first: {1}."
                             .format(host, gai[0]))

        family, _, _, _, hostport = gai[0]
        if family == AF_INET:
            host, port = hostport
        elif family == AF_INET6:
            host, port, _, _ = hostport
        else:
            assert False, "Unknown family: {0}".format(family)

        self.host = host
        self.port = port
        self.family = family
        self.group_id = group_id

    @classmethod
    def from_host_port(cls, addr_str, group_id=0):
        """
        Creates address from string "host:port" and optional group_id.\n
        address = elliptics.Address.from_host_port(addr_str='host.com:1025',
                                                   group_id=0)
        """
        host, port = addr_str.rsplit(':', 1)
        return cls(host=host, port=int(port), family=0, group_id=group_id)

    @classmethod
    def from_host_port_family(cls, addr_str, group_id=0):
        """
        Creates address from string "host:port:family" and optional group_id.\n
        address = elliptics.Address.from_host_port_family(addr_str='host.com:1025:2',
                                                          group_id=0)
        """
        host, port, family = addr_str.rsplit(':', 2)
        return cls(host=host, port=int(port),
                   family=int(family), group_id=group_id)

    def __hash__(self):
        """
        x.__hash__() <==> hash(x)
        """
        return hash(tuple(self))

    def __repr__(self):
        """
        x.__repr__() <==> repr(x)
        """
        return "Address({0}, {1}, {2}, {3})".format(self.host, self.port,
                                                    self.family, self.group_id)

    def __str__(self):
        """
        x.__str__() <==> str(x)
        """
        return "{0}:{1}:{2} {3}".format(self.host, self.port,
                                        self.family, self.group_id)

    def __iter__(self):
        """
        x.__iter__() <==> iter(x)
        """
        return iter((self.host, self.port, self.family))

    def __eq__(self, other):
        """
        x.__eq__(y) <==> x==y
        """
        if other is None:
            return False

        return (self.host, self.port, self.family) == \
               (other.host, other.port, other.family)

    def __ne__(self, other):
        """
        x.__ne__(y) <==> x!=y
        """
        return not self.__eq__(other)

    def __getitem__(self, item):
        """
        x.__getitem__(y) <==> x[y]
        """
        return tuple(self)[item]


class Route(object):
    """
    Simple route container.
    Route consists of key and address to which this key belongs
    """
    __slots__ = ('key', 'address')

    def __init__(self, key, address):
        self.key = key
        self.address = address

    def __hash__(self):
        return hash(tuple(self))

    def __repr__(self):
        return 'Route({0}, {1})'.format(repr(self.key), repr(self.address))

    def __str__(self):
        return 'Route({0}, {1})'.format(self.key, self.address)

    def __iter__(self):
        return iter((self.key, self.address))

    def __eq__(self, other):
        return tuple(self) == tuple(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getitem__(self, item):
        return tuple(self)[item]


class RouteList(object):
    """
    Route list that sorts entries by key and also merges
    keys that belongs to the same node.
    """

    def __init__(self, routes):
        """
        Initializes route list by list of routes.
        """
        self.routes = routes

    @classmethod
    def from_routes(cls, routes):
        """
        Create RouteList from elliptics route table.

        It slightly mangles route list by explicitly inserting start and end of
        hash-ring and also merging adj. routes for the same into one.
        """
        sorted_routes = []

        # First pass - sort keys and construct addresses from text routes
        for key, str_address in sorted(routes, key=lambda route: route[0].id):
            address = Address.from_host_port(str_address, key.group_id)
            sorted_routes.append(Route(key, address))

        # Merge adj. keys for same address
        smallest_id = [0] * 64
        biggest_id = [255] * 64
        merged_routes = []
        for group in cls(sorted_routes).groups():
            group_routes = cls(sorted_routes).filter_by_group_id(group).routes
            last_address = group_routes[-1].address
            merged_group = []

            # Insert implicit first route if needed
            if group_routes[0].key.id != smallest_id:
                group_routes.insert(0, Route(Id(smallest_id, group), last_address))

            # For each Route in list left only first one for each route
            for _, g in groupby(group_routes, attrgetter('address')):
                merged_group.append(list(g)[0])
            assert(all(r1.address != r2.address
                       for r1, r2 in izip(merged_group, merged_group[1:])))
            assert(all(r1.key < r2.key
                       for r1, r2 in izip(merged_group, merged_group[1:])))

            # Insert implicit last route if needed
            if group_routes[-1].key.id != biggest_id:
                merged_group.append(Route(Id(biggest_id, group), last_address))

            # Extend route list
            merged_routes.extend(merged_group)

        # Sort results by key
        merged_routes.sort(key=itemgetter(0))

        # Return RouteList from sorted and merged routes
        return cls(merged_routes)

    def filter_by_address(self, address):
        """
        Filters routes for specified address\n
        routes = routes.filter_by_address(Address.from_host_port_family('host.com:1025:2'))
        """
        return RouteList([route for route in self.routes
                          if route.address == address])

    def filter_by_group_id(self, group_id):
        """
        Filters routes for specified group_id\n
        routes = routes.filter_by_group_id(1)
        """
        return self.filter_by_group_ids([group_id])

    def filter_by_group_ids(self, group_ids):
        """
        Filters routes for specified group_ids\n
        routes = routes.filter_by_group_ids([1, 2, 3])
        """
        return RouteList([route for route in self.routes
                          if route.address.group_id in group_ids])

    def groups(self):
        """
        Returns all groups which are presented in route table\n
        groups = routes.groups()
        """
        return list(set(route.address.group_id for route in self.routes))

    def addresses(self):
        """
        Returns all addresses which are presented in route table\n
        addresses = routes.addresses()
        """
        return list(set(route.address for route in self.routes))

    def addresses_with_id(self):
        """
        Returns all addresses with elliptics.Id which are presented in routes\n
        addresses_with_id = routes.addresses_with_id()
        """
        res = dict()
        for route in self.routes:
            if route.address not in res:
                res[route.address] = route.key
        return res.items()

    def get_address_group_id(self, address):
        """
        Returns group_id of address based on route table\n
        group_id = routes.get_address_group_id(Address.from_host_port_family('host.com:1025:2'))
        """
        return self.filter_by_address(address)[0].key.group_id

    def get_address_id(self, address):
        """
        Returns first key for specified address from route table\n
        id = routes.get_address_id(Address.from_host_port_family('host.com:1025:2'))
        """
        return self.filter_by_address(address)[0].key

    def get_address_eid(self, address):
        """
        Returns first key for specified address from route table
        """
        return self.get_address_id(address)

    def get_address_ranges(self, address):
        """
        Returns key ranges which belong to specified address\n
        ranges = routes.get_address_ranges(Address.from_host_port_family('host.com:1025:2'))
        """
        ranges = []
        group_id = self.get_address_group_id(address)
        key = None
        for route in self.filter_by_group_id(group_id):
            if route.address == address:
                if key is None:
                    key = route.key
            elif key:
                ranges.append((key, route.key))
                key = None

        if key:
            ranges.append((key, Id([255] * 64, group_id)))

        return ranges

    def percentages(self):
        """
        Returns parts of DHT ring each node occupies (in percents)\n
        print routes.percentages()
        """
        perc = {}
        for g in self.groups():
            routes = self.filter_by_group_id(g)
            prev = None
            perc[g] = {}
            for r in routes:
                if prev:
                    amount = int(str(r.key), 16) - int(str(prev.key), 16)
                    if prev.address not in perc[g]:
                        perc[g][prev.address] = amount
                    else:
                        perc[g][prev.address] += amount

                prev = r

        max = int(str(Id([255] * 64, 0)), 16)

        for g in perc:
            sum = 0
            for p in perc[g]:
                sum += perc[g][p]
                perc[g][p] = perc[g][p] * 100.0 / max
            assert(sum == max)

        return perc

    def spread(self):
        return self.percentages()

    def __iter__(self):
        """x.__iter__() <==> iter(x)"""
        return iter(self.routes)

    def __len__(self):
        """x.__len__() <==> len(x)"""
        return len(self.routes)

    def __nonzero__(self):
        """x.__nonzero__() <==> bool(x)"""
        return len(self)

    def __getitem__(self, item):
        """x.__getitem__(y) <==> x[y]"""
        return self.routes[item % len(self.routes)]

    def __str__(self):
        """x.__str__() <==> str(x)"""
        return "\n".join(map(str, self.routes))
