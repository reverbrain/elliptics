#!/usr/bin/python
# -*- coding: utf-8 -*-

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

from elliptics import *

def upload_file(node, filename):
	f = open(filename, 'r')
	content = 'content_data = """' + f.read() + '"""\ncontent_filename = \'www.example.com' + filename + '\'';
	f.close()

	node.exec_name(filename, "script.py", content, 1)

try:
	cfg = Config()
	cfg.config.wait_timeout = 30
	cfg.config.check_timeout = 120

	log = Logger("/dev/stderr", 2)
	n = Node(log, cfg)

	n.add_groups([1,2,3])
	remotes = [("172.16.136.1", 1025)]

	for r in remotes:
		try:
			n.add_remotes(elliptics.Address(r[0], r[1], 2))
		except:
			pass
	if len(n.get_routes()) == 0:
		raise NameError("No routes added")

	script = 'import time, socket\n__return_data="run at: " + socket.gethostname() + ": " + time.ctime(time.time()) + "   " + str(__input_binary_data_tuple[0])'
	binary='this is binary data\n'

	id = []
	group_id = 0
	print n.exec_script(script, binary, 2)
	exit(0)

	for dirname, dirnames, filenames in os.walk('/tmp/directory'):
		for subdirname in dirnames:
			print os.path.join(dirname, subdirname)
		for filename in filenames:
			path = os.path.join(dirname, filename)
			print path
			upload_file(n, path)

except Exception as e:
	print "Could not initialize node", e
