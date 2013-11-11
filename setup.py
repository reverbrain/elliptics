#!/usr/bin/env python
# vim: set ts=4:sw=4:expandtab:

# =============================================================================
# 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

from distutils.core import setup

vstr = '0.0.1'
try:
    f = open('debian/changelog')
    qstr = f.readline()
    vstr = '.'.join(qstr.split()[1].strip("()").split(".")[:2])
    f.close()
except:
    pass

print vstr
setup(name = 'elliptics',
      version = vstr,
      description = 'Elliptics - client library for distributed storage system',
      url = 'http://www.ioremap.net/projects/elliptics',
      package_dir = {'elliptics': 'bindings/python/src'},
      packages = ['elliptics'],
      license = 'GPLv2',
     )

setup(name = 'elliptics_recovery',
      version = vstr,
      description = 'Elliptics - data center and merge recovery module',
      url = 'http://www.ioremap.net/projects/elliptics',
      package_dir = {
          'elliptics_recovery': 'recovery/elliptics_recovery',
          'elliptics_recovery/types': 'recovery/elliptics_recovery/types',
          'elliptics_recovery/utils': 'recovery/elliptics_recovery/utils',
          },
      packages = ['elliptics_recovery', 'elliptics_recovery/types', 'elliptics_recovery/utils'],
      data_files = [('bin', ['recovery/dnet_recovery'])],
      license = 'GPLv2',
      )
