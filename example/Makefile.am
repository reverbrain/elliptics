bin_PROGRAMS = dnet_ioserv dnet_hparser dnet_stat dnet_notify dnet_ioclient dnet_monitor dnet_check dnet_ids
noinst_LIBRARIES = libcommon.a libbackend.a
noinst_HEADERS = backends.h common.h hash.h
SUBDIRS = .
#SUBDIRS += check

CC = @PTHREAD_CC@

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@

EXAMPLE_COMMON_LIBS = ../library/libelliptics.la libcommon.a

libcommon_a_SOURCES = common.c hash.c
libbackend_a_SOURCES = file_backend.c backends.c

if HAVE_EBLOB
AM_CFLAGS += @EBLOB_CFLAGS@
AM_LDFLAGS += @EBLOB_LIBS@
libbackend_a_SOURCES += eblob_backend.c 

if HAVE_BOOST_ASIO
bin_PROGRAMS += dnet_eblob_from_tar

AM_CXXFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@

dnet_eblob_from_tar_SOURCES = eblob_from_tar.cpp
dnet_eblob_from_tar_LDADD = @BOOST_ASIO_LIB@ ../bindings/cpp/libelliptics_cpp.la
endif
endif

EXAMPLE_BACKEND_LIBS = libbackend.a

dnet_ioserv_SOURCES = ioserv.c config.c
dnet_ioserv_LDADD = $(EXAMPLE_COMMON_LIBS) $(EXAMPLE_BACKEND_LIBS)

dnet_check_SOURCES = check.c
dnet_check_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_ioclient_SOURCES = ioclient.c
dnet_ioclient_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_hparser_SOURCES = hparser.c
dnet_hparser_LDADD = ../library/libelliptics.la

dnet_stat_SOURCES = stat.c
dnet_stat_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_monitor_SOURCES = monitor.c
dnet_monitor_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_notify_SOURCES = notify.c
dnet_notify_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_ids_SOURCES = ids.c

if HAVE_FASTCGI
SUBDIRS += fcgi
endif

EXTRA_DIST = EXAMPLE 00-INDEX ioserv.conf
