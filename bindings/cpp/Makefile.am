bin_PROGRAMS = dnet_cpp_test
lib_LTLIBRARIES = libelliptics_cpp.la

libelliptics_cpp_la_SOURCES = elliptics_log.cpp elliptics_node.cpp elliptics_callback.cpp
libelliptics_cpp_la_LIBADD = ../../library/libelliptics.la

dnet_cpp_test_SOURCES = test.cpp
dnet_cpp_test_LDADD = libelliptics_cpp.la

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@
