bin_PROGRAMS = dnet_ioserv dnet_hparser dnet_iotest dnet_stat dnet_notify dnet_ioclient
noinst_LIBRARIES = libcommon.a libbackend.a
noinst_HEADERS = hash.h backends.h common.h
SUBDIRS = blob . check cpp

CC = @PTHREAD_CC@

EXAMPLE_COMMON_LIBS = ../library/libelliptics.la libcommon.a

libcommon_a_SOURCES = common.c hash.c lookup3.c
libbackend_a_SOURCES = file_backend.c backends.c

if HAVE_TOKYOCABINET
libbackend_a_SOURCES += tc_backend.c 
endif

EXAMPLE_BACKEND_LIBS = libbackend.a blob/libblob_backend.a

dnet_ioserv_SOURCES = ioserv.c config.c
dnet_ioserv_LDADD = $(EXAMPLE_COMMON_LIBS) $(EXAMPLE_BACKEND_LIBS)

dnet_ioclient_SOURCES = ioclient.c
dnet_ioclient_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_hparser_SOURCES = hparser.c
dnet_hparser_LDADD = ../library/libelliptics.la

dnet_iotest_SOURCES = iotest.c
dnet_iotest_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_stat_SOURCES = stat.c
dnet_stat_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_notify_SOURCES = notify.c
dnet_notify_LDADD = $(EXAMPLE_COMMON_LIBS)

if HAVE_FASTCGI
SUBDIRS += fcgi
endif

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @TOKYOCABINET_LIBS@

EXTRA_DIST = EXAMPLE 00-INDEX ioserv.conf
