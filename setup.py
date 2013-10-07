#!/usr/bin/env python
# vim: set ts=4:sw=4:expandtab:

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
      py_modules = ['elliptics'],
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
      data_files = [('/usr/bin', ['recovery/dnet_recovery'])],
      license = 'GPLv2',
      )
