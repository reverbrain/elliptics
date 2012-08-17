#!/usr/bin/env python

from distutils.core import setup

vstr = '0.0.1'
try:
	f = open('../../../configure.in')
	vstr = f.readline()

	count = 0
	version = ''
	for c in vstr:
		if c == '[':
			count += 1
		elif count == 2:
			if c == ']':
				break

			version += c
	if len(version) != 0:
		vstr = version
	f.close()
except:
	pass

setup(name='elliptics',
      version=vstr,
      description='Elliptics - client library for distributed storage system',
      author='Anton Kortunov',
      author_email='toshic.toshic@gmail.com',
      url='http://www.ioremap.net/projects/elliptics',
      py_modules=['elliptics']
     )
