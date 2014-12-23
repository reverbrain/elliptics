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

from elliptics.core import Id
from elliptics.log import logged_class


def convert_to_list(key):
    id = []
    while key > 0:
        id = [key % 256] + id
        key /= 256
    if len(id) < 64:
        id = [0] * (64 - len(id)) + id
    return id[:64]


@logged_class
class Id(Id):
    def __init__(self, key, group=0):
        import types
        if type(key) is str:
            super(Id, self).__init__(convert_to_list(int(key, 16)), group)
        elif type(key) in (long, int):
            super(Id, self).__init__(convert_to_list(key), group)
        elif type(key) in (tuple, list, types.GeneratorType, xrange):
            super(Id, self).__init__(key, group)
        else:
            raise TypeError("elliptics.Id can not be initialized by '{0}' object".format(type(key)))
