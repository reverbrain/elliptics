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

from socket import getaddrinfo, SOL_TCP, AF_INET6, AF_INET, AF_UNSPEC
from elliptics.core import Id
from elliptics.log import logged_class


@logged_class
class Address(object):
    """
    Address wrapper. Resolves a hostname into IP addresses and uses
    the first address if the given hostname is resolved into more then one.
    """
    # Allowed families, AF_UNSPEC means any
    ALLOWED_FAMILIES = (AF_UNSPEC, AF_INET, AF_INET6)

    def __init__(self, host, port=None, family=AF_UNSPEC):
        """
        Initializes Address from host, port and optional family\n
        address = elliptics.Address(host='host.com', port=1025,
                                    family=2)
        """
        if family not in self.ALLOWED_FAMILIES:
            raise ValueError("Family '{0}' is not in {1}"
                             .format(family, self.ALLOWED_FAMILIES))

        gai = getaddrinfo(host, port, family, 0, SOL_TCP)
        if len(gai) > 1:
            self.log.warning("More than one IP found "
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

    @classmethod
    def from_host_port(cls, addr_str):
        """
        Creates address from string "host:port".\n
        address = elliptics.Address.from_host_port(addr_str='host.com:1025')
        """
        host, port = addr_str.rsplit(':', 1)
        return cls(host=host, port=int(port), family=AF_UNSPEC)

    @classmethod
    def from_host_port_family(cls, addr_str):
        """
        Creates address from string "host:port:family".\n
        address = elliptics.Address.from_host_port_family(addr_str='host.com:1025:2')
        """
        host, port, family = addr_str.rsplit(':', 2)
        return cls(host=host, port=int(port), family=int(family))

    def __hash__(self):
        """
        x.__hash__() <==> hash(x)
        """
        return hash(tuple(self))

    def __repr__(self):
        """
        x.__repr__() <==> repr(x)
        """
        return "<Address: {0}:{1}:{2}>".format(self.host, self.port, self.family)

    def __str__(self):
        """
        x.__str__() <==> str(x)
        """
        return "{0}:{1}:{2}".format(self.host, self.port, self.family)

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

        return tuple(self) == tuple(other)

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
    Route consists of id, address and backend_id to which this id belongs
    """
    __slots__ = ('id', 'address', 'backend_id')

    def __init__(self, id, address, backend_id):
        self.id = id
        self.address = address
        self.backend_id = backend_id

    def __hash__(self):
        return hash(tuple(self))

    def __repr__(self):
        return '<Route: {0}, {1}, <backend_id: {2}>>'.format(repr(self.id), repr(self.address), repr(self.backend_id))

    def __str__(self):
        return 'Route({0}:{1}, {2}/{3})'.format(self.id.group_id, self.id, self.address, self.backend_id)

    def __iter__(self):
        return iter((self.id, self.address, self.backend_id))

    def __eq__(self, other):
        return tuple(self) == tuple(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getitem__(self, item):
        return tuple(self)[item]


class RouteList(object):
    """
    Route list that sorts entries by id and also merges
    ids that belongs to the same node.
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
        routes_dict = dict()

        # splits all routes between groups
        for r in routes:
            if r.id.group_id in routes_dict:
                routes_dict[r.id.group_id].append(Route(r.id, r.address, r.backend_id))
            else:
                routes_dict[r.id.group_id] = [Route(r.id, r.address, r.backend_id)]

        # merges adj. ids for same address
        smallest_id = [0] * 64
        biggest_id = [255] * 64
        merged_routes = []
        for group in routes_dict:
            # sorts routes inside one group
            group_routes = sorted(routes_dict[group], key=lambda route: route.id)
            last = (group_routes[-1].address,
                    group_routes[-1].backend_id)

            # Insert implicit first route if needed
            if group_routes[0].id.id != smallest_id:
                route = Route(Id(smallest_id, group), *last)
                group_routes.insert(0, route)

            # Insert implicit last route if needed
            if group_routes[-1].id.id != biggest_id:
                route = Route(Id(biggest_id, group), *last)
                group_routes.append(route)

            # Extend route list
            merged_routes.extend(group_routes)

        # Sort results by key
        merged_routes.sort(key=lambda route: route.id)

        # Return RouteList from sorted and merged routes
        return cls(merged_routes)

    def filter_by_address(self, address):
        """
        Filters routes for specified address\n
        address = Address.from_host_port_family('host.com:1025:2')
        routes = routes.filter_by_address(address)
        """
        return RouteList([route for route in self.routes
                          if route.address == address])

    def filter_by_group(self, group_id):
        """
        Filters routes for specified group_id\n
        routes = routes.filter_by_group(1)
        """
        return self.filter_by_groups([group_id])

    def filter_by_groups(self, group_ids):
        """
        Filters routes for specified group_ids\n
        routes = routes.filter_by_groups((1, 2, 3))
        """
        return RouteList([route for route in self.routes
                          if route.id.group_id in group_ids])

    def filter_by_backend(self, backend_id):
        """
        Filters routes for specified backend_id\n
        routes = routes.filter_by_backend((1, 2, 3))
        """
        return RouteList([route for route in self.routes
                          if route.backend_id == backend_id])

    def groups(self):
        """
        Returns all groups which are presented in route table\n
        groups = routes.groups()
        """
        return tuple(set(route.id.group_id for route in self.routes))

    def addresses(self):
        """
        Returns all addresses which are presented in route table\n
        addresses = routes.addresses()
        """
        return tuple(set(route.address for route in self.routes))

    def addresses_with_backends(self):
        """
        Returns all addresses and backend_ids which are presented in route table\n
        addresses = routes.addresses_with_backends()
        """
        return tuple(set((route.address, route.backend_id) for route in self.routes))

    def get_unique_routes(self):
        """
        Returns unique by address, group_id and backend_id which are presented in routes\n
        This routes can be used for routing request to backend on node from group.\n
        unique_routes = routes.get_unique_routes()
        """
        tmp = set()

        def seen(route):
            val = (route.address, route.id.group_id, route.backend_id)
            return val in tmp or tmp.add(val)

        return tuple(route for route in self.routes if not seen(route))

    def get_id_routes(self, id):
        """
        Returns tuple of (address, group, backend)s that responsible for the id.

        id_routes = routes.get_id_routes(id)
        """
        from bisect import bisect
        route_id = bisect([r.id for r in self.routes], id) - 1
        group_dict = {}
        while route_id > -1 and len(group_dict) != len(self.groups()):
            route = self.routes[route_id]
            if route.id.group_id not in group_dict:
                group_dict[route.id.group_id] = (route.address, route.backend_id)
            route_id -= 1

        return tuple((address, group, backend) for group, (address, backend) in group_dict.items())

    def get_address_unique_routes(self, address):
        """
        Returns address routes unique by backend_id.
        """
        tmp = set()

        def seen(route):
            return route.backend_id in tmp or tmp.add(route.backend_id)
        return tuple(route for route in self.routes if route.address == address and not seen(route))

    def get_address_backend_routes(self, address, backend_id):
        """
        Returns all routes for specified @address and @backend_id
        """
        return tuple(route for route in self.routes if (route.address, route.backend_id) == (address, backend_id))

    def get_address_backend_route_id(self, address, backend_id):
        """
        Returns only elliptics.Id from all routes for specified @address and @backend_id
        """
        return next(route.id for route in self.routes if (route.address, route.backend_id) == (address, backend_id))

    def get_address_backend_group(self, address, backend_id):
        """
        Returns group's id of specified @backend_id at node @address
        """
        return next(route.id.group_id for route in self.routes
                    if route.address == address and route.backend_id == backend_id)

    def get_address_groups(self, address):
        """
        Returns all group_ids of address based on route table\n
        groups = routes.get_address_groups(
            Address.from_host_port_family('host.com:1025:2'))
        """
        return tuple(set(route.id.group_id for route in self.routes if route.address == address))

    def get_address_backends(self, address):
        """
        Returns all backend_ids presented at @address
        """
        return tuple(set(route.backend_id for route in self.routes if route.address == address))

    def get_address_ranges(self, address):
        """
        Returns id ranges which belong to specified @address\n
        ranges = routes.get_address_ranges(
            Address.from_host_port_family('host.com:1025:2'))
        """
        ranges = []
        groups = self.get_address_groups(address)
        id = None
        for route in self.filter_by_groups(groups):
            if route.address == address:
                if id is None:
                    id = route.id
            elif id:
                ranges.append((id, route.id))
                id = None

        if id:
            ranges.append((id, Id([255] * 64, id.group_id)))

        return ranges

    def get_address_backend_ranges(self, address, backend_id):
        """
        Returns id ranges which belong to specified @backend_id at @address\n
        ranges = routes.get_address_backend_ranges(
            Address.from_host_port_family('host.com:1025:2', 0))
        """
        ranges = []
        group = self.get_address_backend_group(address, backend_id)
        id = None
        for route in self.filter_by_groups([group]):
            if (route.address, route.backend_id) == (address, backend_id):
                if id is None:
                    id = route.id
            elif id:
                ranges.append((id, route.id))
                id = None
        if id:
            ranges.append((id, Id([255] * 64, id.group_id)))
        return ranges

    def percentages(self):
        """
        Returns parts of DHT ring each node and each node backend occupies (in percents)\n
        print routes.percentages()
        """
        perc = {}
        for group in self.groups():
            routes = self.filter_by_group(group)
            perc[group] = {}
            for i, r in enumerate(routes[1:]):
                prev = routes[i]
                amount = int(str(r.id), 16) - int(str(prev.id), 16)
                if prev.address not in perc[group]:
                    perc[group][prev.address] = {prev.backend_id: amount}
                elif prev.backend_id not in perc[group][prev.address]:
                    perc[group][prev.address][prev.backend_id] = amount
                else:
                    perc[group][prev.address][prev.backend_id] += amount

        max = int(str(Id([255] * 64, 0)), 16)

        for group in perc:
            sum = 0
            for address in perc[group]:
                address_sum = 0
                for backend in perc[group][address]:
                    sum += perc[group][address][backend]
                    address_sum += perc[group][address][backend]
                    perc[group][address][backend] = perc[group][address][backend] * 100.0 / max
                perc[group][address]['total'] = address_sum * 100.0 / max
            assert(sum == max)

        return perc

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
        if not len(self.routes):
            raise IndexError("index out of range")
        return self.routes[item]

    def __repr__(self):
        return "(" + ",\n".join(map(repr, self.routes)) + ")"

    def __str__(self):
        """x.__str__() <==> str(x)"""
        return "\n".join(map(str, self.routes))
