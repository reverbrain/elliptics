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

from elliptics.core import Session
from elliptics.route import RouteList, Address
from elliptics.log import logged_class


@logged_class
class Session(Session):

    @property
    def routes(self):
        return self.get_routes()

    def get_routes(self):
        return RouteList.from_routes(super(Session, self).get_routes())

    def lookup_address(self, key, group_id):
        return Address.from_host_port(super(Session, self)
                                      .lookup_address(key, group_id), group_id)
