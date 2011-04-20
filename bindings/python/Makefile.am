lib_LTLIBRARIES = libelliptics_python.la

libelliptics_python_la_SOURCES = elliptics_python.cpp
libelliptics_python_la_LIBADD = -L../../library/ -lelliptics -L../cpp/ -lelliptics_cpp @BOOST_PYTHON_LDFLAGS@

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @PYTHON_CPPFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @PYTHON_LDFLAGS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BOOST_PYTHON_LDFLAGS@
