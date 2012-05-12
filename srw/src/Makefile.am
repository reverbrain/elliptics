bin_PROGRAMS = srw_worker srw_test
lib_LTLIBRARIES = libsrw.la

srw_test_SOURCES = test.cpp
srw_worker_SOURCES = worker.cpp
libsrw_la_SOURCES = srwc.cpp

AM_CXXFLAGS = -I@top_srcdir@/include -I. -I@top_srcdir@/config @BOOST_CPPFLAGS@ @PYTHON_CPPFLAGS@ @EBLOB_CFLAGS@
AM_LDFLAGS = @VERSION_INFO@ @BOOST_THREAD_LIB@ @BOOST_LDFLAGS@ @PYTHON_LDFLAGS@ @PYTHON_EXTRA_LDFLAGS@
