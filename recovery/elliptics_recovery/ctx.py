# =============================================================================
# 2013+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
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
Recovery context is just a configuration of recovery process
"""

from pprint import pformat
from copy import copy


class Ctx(object):
    """
    Tiny wrapper for dict with better interface:
    Now you can use ctx.test = 'test', instead of ctx['test'] = 'test'
    """
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def portable(self):
        '''
        Makes lightweight copy of context that can be used by multiprocessing
        '''
        tmp = copy(self.__dict__)
        if 'pool' in tmp:
            del tmp['pool']
        return Ctx(**tmp)

    def __repr__(self):
        return pformat(self.__dict__, indent=4)
