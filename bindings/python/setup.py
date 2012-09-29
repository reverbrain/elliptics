#!/usr/bin/env python

import shutil

from distutils.core import setup
from distutils.core import Extension

from distutils.command.build_ext import build_ext as _build_ext
from distutils.command.install_lib import install_lib as _install_lib

class build_ext(_build_ext):
	def run(self):
		pass


class install_lib(_install_lib):
	def run(self):
		self.mkpath(self.install_dir)
		shutil.copy('libelliptics_python.so', self.install_dir)

		_install_lib.run(self)

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
