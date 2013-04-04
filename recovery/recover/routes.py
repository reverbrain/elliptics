from .misc import logged_class, format_id

__doc__ = \
"""
Route management routines

Vanilla elliptics python bindings are too C'ish.
We need better abstractions.
"""

@logged_class
class Route(object):
    __doc__ = """
              Simple route container.
              Right now route consists of key and node to which this key belongs
              """
    __slots__ = ('key', 'node')
    def __init__(self, key, node):
        self.key = key
        self.node = node

    def __repr__(self):
        return 'Route({0}, {1})'.format(repr(self.key), repr(self.node))

    def __str__(self):
        return 'Route({0}, {1})'.format(format_id(self.key.id), self.node)

    def __iter__(self):
        return iter((self.key, self.node))

    def __eq__(self, other):
        return self.key == other.key and self.node == other.node

@logged_class
class RouteList(object):
    __doc__ = """
              Route list that sorts entries by key and also merges
              adj. keys that belongs to the same node.
              """
    def __init__(self, routes):
        unmerged_routes = []
        self.log.debug("Routes recv'd: {0}".format(len(routes)))

        # First pass - sort keys
        for key, node in sorted(routes, key=lambda route: route[0].id):
            unmerged_routes.append(Route(key, node))
        self.log.debug("Routes after sort: {0}".format(len(unmerged_routes)))
        assert len(routes) == len(unmerged_routes)

        # Second pass - merge adj. keys for same node
        self.routes = []
        for i, route in enumerate(unmerged_routes):
            key, node = route
            _, prev_node = unmerged_routes[(i + 1) % len(unmerged_routes)]
            if prev_node != node:
                self.routes.append(route)
        assert len(self.routes) <= len(unmerged_routes)
        self.log.debug("Routes after merge: {0}".format(len(self.routes)))

    def __iter__(self):
        return iter(self.routes)

    def __len__(self):
        return len(self.routes)

    def __nonzero__(self):
        return len(self)

    def __getitem__(self, item):
        """Get item with wraparound"""
        return self.routes[item % len(self)]

    def __str__(self):
        return "\n".join(route for route in self)
