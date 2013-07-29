"""
Route management routines

Vanilla elliptics python bindings are too C'ish.
We need better abstractions.
"""

from socket import getaddrinfo, SOL_TCP, AF_INET6, AF_INET
from itertools import groupby
from operator import itemgetter

from .utils.misc import logged_class
from .range import IdRange, RecoveryRange, AddressRanges


@logged_class
class Address(object):
    __doc__ = \
        """
        Address wrapper. Resolves host names into IP addresses.
        """
    # Allowed families, 0 means any
    ALLOWED_FAMILIES = (0, AF_INET, AF_INET6)

    def __init__(self, host=None, port=None, family=0):
        if family not in self.ALLOWED_FAMILIES:
            raise ValueError("Family '{0}' is not in {1}".format(family, self.ALLOWED_FAMILIES))

        gai = getaddrinfo(host, port, family, 0, SOL_TCP)
        if len(gai) > 1:
            self.log.warning("More than one IP found for: {0}. Using first: {1}.".format(host, gai[0]))

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
        Creates address from string.
        """
        host, port = addr_str.rsplit(':', 1)
        return cls(host=host, port=int(port), family=0)

    @classmethod
    def from_host_port_family(cls, addr_str):
        host, port, family = addr_str.rsplit(':', 2)
        return cls(host=host, port=int(port), family=int(family))

    def __hash__(self):
        return hash(tuple(self))

    def __repr__(self):
        return "Address({0}, {1}, {2})".format(self.host, self.port, self.family)

    def __str__(self):
        return "{0}:{1}:{2}".format(self.host, self.port, self.family)

    def __iter__(self):
        return iter((self.host, self.port, self.family))

    def __eq__(self, other):
        return tuple(self) == tuple(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getitem__(self, item):
        return tuple(self)[item]


@logged_class
class Route(object):
    __doc__ = \
        """
        Simple route container.
        Right now route consists of key and address to which this key belongs
        """
    __slots__ = ('key', 'address')
    def __init__(self, key, address):
        self.key = key
        self.address = address

    def __hash__(self):
        return hash(tuple(self))

    def __repr__(self):
        return 'Route({0}, {1}, {2})'.format(repr(self.key), repr(self.address), self.key.group_id)

    def __str__(self):
        return 'Route({0}, {1}, {2})'.format(self.key, self.address, self.key.group_id)

    def __iter__(self):
        return iter((self.key, self.address))

    def __eq__(self, other):
        return tuple(self) == tuple(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getitem__(self, item):
        return tuple(self)[item]

@logged_class
class RouteList(object):
    __doc__ = \
        """
        Route list that sorts entries by key and also merges
        adj. keys that belongs to the same node.
        """
    def __init__(self, routes):
        self.routes = routes

    @classmethod
    def from_session(cls, session):
        """
        Create RouteList from elliptics session.
        """
        routes = session.get_routes()
        sorted_routes = []

        # First pass - sort keys and construct addresses text routes
        for key, str_address in sorted(routes, key=lambda route: route[0].id):
            address = Address.from_host_port(str_address)
            sorted_routes.append(Route(key, address))

        # Second pass - merge adj. keys for same address
        merged_routes = []
        for k, g in groupby(sorted_routes, itemgetter(1)):
            merged_routes.append(list(g)[0])
        assert len(merged_routes) <= len(sorted_routes)

        # Remove first route if it equals the last one
        if len(merged_routes) > 1:
            if merged_routes[-1].address == merged_routes[0].address:
                merged_routes.pop(0)

        # Return RouteList from sorted and merged routes
        return cls(merged_routes)

    def filter_by_address(self, address):
        return [ route for route in self.routes if route.address == address ]

    def filter_by_group_id(self, group_id):
        return [ route for route in self.routes if route.key.group_id == group_id ]

    def groups(self):
        return list(set(route.key.group_id for route in self.routes))

    def addresses(self):
        return list(set(route.address for route in self.routes))

    def get_address_group_id(self, address):
        return self.filter_by_address(address)[0].key.group_id

    def get_address_eid(self, address):
        return self.filter_by_address(address)[0].key

    def get_ranges_by_address(self, address):
        ranges = []
        group_id = self.filter_by_address(address)[0].key.group_id
        keys = dict()
        include = False
        for route in self.routes:
            keys[route.key.group_id] = (route.key, route.address)
            if route.key.group_id == group_id:
                include = route.address == address

        if include:
            ranges.append(RecoveryRange(IdRange(IdRange.ID_MIN, self.routes[0].key), keys.copy()))

        for i, route in enumerate(self.routes):
            keys[route.key.group_id] = (route.key, route.address)
            if i < len(self.routes) - 1:
                next_route = self.routes[i + 1].key
            else:
                next_route = IdRange.ID_MAX

            if route.key.group_id != group_id and not include:
                continue

            if route.address == address:
                include = True
                ranges.append(RecoveryRange(IdRange(route.key, next_route), keys.copy()))
            elif route.key.group_id == group_id:
                include = False
            elif include:
                ranges.append(RecoveryRange(IdRange(route.key, next_route), keys.copy()))

        return ranges

    def get_local_ranges_by_address(self, address):
        ranges = self.get_ranges_by_address(address)
        result = dict((address, AddressRanges(address=address, eid=self.get_address_eid(address), id_ranges=[])) for address in self.addresses())

        for r in ranges:
            for group_id in r.address:
                address = r.address[group_id][1]
                assert result[address].eid.group_id == group_id
                result[address].id_ranges.append(r.id_range)

        return [v for v in result.values() if len(v.id_ranges)]

    def __iter__(self):
        return iter(self.routes)

    def __len__(self):
        return len(self.routes)

    def __nonzero__(self):
        return len(self)

    def __getitem__(self, item):
        """Get item with wraparound"""
        return self.routes[item % len(self.routes)]

    def __str__(self):
        return "\n".join(map(str, self.routes))
