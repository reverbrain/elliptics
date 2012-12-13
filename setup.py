#!/usr/bin/env python

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
setup(name='elliptics',
      version=vstr,
      description='Elliptics - client library for distributed storage system',
      url='http://www.ioremap.net/projects/elliptics',
      package_dir = {'': 'bindings/python'},
      py_modules=['elliptics'],
      license = 'GPLv2',
     )
