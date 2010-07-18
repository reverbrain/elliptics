#!/usr/bin/python

from libelliptics_python import *
from array import *
import struct

id = array('B')
for x in xrange(0, 20) :
	id.append(x + 1)

trans = array('B')
for x in xrange(0, 20) :
	trans.append(1)

log = elliptics_log_file("/dev/stderr", 10)
n = elliptics_node_python(id.buffer_info()[0], log)

t = elliptics_transform_openssl("sha1")

n.add_transform(t)
# weird thing happens if I write n.add_transform(elliptics_transform_openssl("sha1"))
# we crash somewhere inside c++ binding, probably because I implemented lazy
# reference counting model (i.e. not at all :)
# thus object MUST live after this function is completed
# this should be fixed of course with proper copy constructors
# the same applies to logger actually

n.add_remote("localhost", 1025)

n.write_file(trans.buffer_info()[0], "/tmp/test_file", 0, 0, 0)
n.read_file(trans.buffer_info()[0], "/tmp/test_file.read", 0, 0)
