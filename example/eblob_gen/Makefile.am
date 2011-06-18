if HAVE_BOOST_FILESYSTEM
if HAVE_BOOST_PROGRAM_OPTIONS

bin_PROGRAMS = dnet_eblob_gen
noinst_HEADERS = eblob_gen.h

AM_CXXFLAGS = -I../../include -I../../config -I../ @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@
AM_LDFLAGS = @KYOTOCABINET_LIBS@

dnet_eblob_gen_SOURCES = main.cpp dir.cpp eblob_gen.cpp data_source.cpp tar.cpp
dnet_eblob_gen_LDADD = @BOOST_FILESYSTEM_LIB@ @BOOST_PROGRAM_OPTIONS_LIB@ @EBLOB_LIBS@ -leblob_cpp \
		       ../../library/libelliptics.la ../../bindings/cpp/libelliptics_cpp.la ../libcommon.a \
		       -ltar

if HAVE_BOOST_IOSTREAMS
if HAVE_BOOST_THREAD

bin_PROGRAMS += dnet_meta_update_all

dnet_meta_update_all_SOURCES = meta_update.cpp
dnet_meta_update_all_LDADD = ../../bindings/cpp/libelliptics_cpp.la ../../library/libelliptics.la \
				     @BOOST_IOSTREAMS_LIB@ @BOOST_THREAD_LIB@ @BOOST_FILESYSTEM_LIB@ \
				     @BOOST_PROGRAM_OPTIONS_LIB@ @EBLOB_LIBS@

endif
endif

endif
endif


