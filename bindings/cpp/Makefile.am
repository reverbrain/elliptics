noinst_PROGRAMS = dnet_cpp_test
lib_LTLIBRARIES = libelliptics_cpp.la

libelliptics_cpp_la_SOURCES = log.cpp node.cpp callback.cpp
libelliptics_cpp_la_LIBADD = ../../library/libelliptics.la @VERSION_INFO@

dnet_cpp_test_SOURCES = test.cpp
dnet_cpp_test_LDADD = libelliptics_cpp.la

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @EBLOB_LIBS@
