lib_LTLIBRARIES = libelliptics_python.la

libelliptics_python_la_SOURCES = elliptics_python.cpp
libelliptics_python_la_LIBADD =  @top_srcdir@/library/.libs/libelliptics.la @top_srcdir@/bindings/cpp/.libs/libelliptics_cpp.la @BOOST_PYTHON_LDFLAGS@

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @PYTHON_CPPFLAGS@  @EBLOB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @PYTHON_LDFLAGS@ @BOOST_PYTHON_LDFLAGS@ \
	     @VERSION_INFO@ @KYOTOCABINET_LIBS@ @EBLOB_LIBS@
