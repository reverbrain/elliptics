if HAVE_BOOST_ASIO
if HAVE_BOOST_FILESYSTEM
if HAVE_BOOST_PROGRAM_OPTIONS

bin_PROGRAMS = dnet_eblob_gen
noinst_HEADERS = eblob_gen.h

AM_CXXFLAGS = -I../../include -I../../config -I../ @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@

dnet_eblob_gen_SOURCES = main.cpp eblob.cpp dir.cpp eblob_gen.cpp data_source.cpp
dnet_eblob_gen_LDADD = @BOOST_ASIO_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_PROGRAM_OPTIONS_LIB@ \
			    @EBLOB_LIBS@ ../../bindings/cpp/libelliptics_cpp.la ../libcommon.a
endif
endif
endif


