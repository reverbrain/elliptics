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

import logging

log = logging.getLogger("elliptics")


def logged_class(klass):
    """
    This decorator adds 'log' method to passed class
    """
    klass.log = logging.getLogger("elliptics")
    return klass


def init_logger():
    import sys
    log.setLevel(logging.ERROR)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(logging.Formatter(fmt='%(asctime)-15s %(processName)s %(levelname)s %(message)s',
                                      datefmt='%d %b %y %H:%M:%S'))
    ch.setLevel(logging.ERROR)
    log.addHandler(ch)
