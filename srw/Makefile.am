lib_LTLIBRARIES = libelliptics_cocaine.la

libelliptics_cocaine_la_SOURCES = srw.cpp

AM_CXXFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @COCAINE_CXXFLAGS@ @EBLOB_CFLAGS@ @MSGPACK_CXXFLAGS@ @ZMQ_CXXFLAGS@ -I../library
AM_LDFLAGS = @COCAINE_LIBS@ @MSGPACK_LIBS@ @ZMQ_LIBS@
