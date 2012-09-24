#!/usr/bin/env python

from distutils.core import setup
from distutils.core import Extension

vstr = '0.0.1'
try:
	f = open('../../CMakeLists.txt')
	
	for qstr in f:
		if 'ELLIPTICS_VERSION_ABI' in qstr:
			vstr = qstr.split()[1].split(')')[0].strip('"')
			break
	f.close()
except:
	pass

setup(name='elliptics',
      version=vstr,
      description='Elliptics - client library for distributed storage system',
      url='http://www.ioremap.net/projects/elliptics',
      py_modules=['elliptics'],
      license = 'GPLv2',
      ext_modules=[Extension('libelliptics_python', [])],
     )
