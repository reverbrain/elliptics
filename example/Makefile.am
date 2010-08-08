bin_PROGRAMS = dnet_ioserv dnet_hparser dnet_iotest dnet_stat dnet_notify dnet_ioclient dnet_monitor
noinst_LIBRARIES = libcommon.a libbackend.a
noinst_HEADERS = hash.h backends.h common.h
SUBDIRS = . check

CC = @PTHREAD_CC@

EXAMPLE_COMMON_LIBS = ../library/libelliptics.la libcommon.a

libcommon_a_SOURCES = common.c hash.c lookup3.c
libbackend_a_SOURCES = file_backend.c backends.c

if HAVE_TOKYOCABINET
libbackend_a_SOURCES += tc_backend.c 
endif

if HAVE_EBLOB
libbackend_a_SOURCES += eblob_backend.c 
endif

EXAMPLE_BACKEND_LIBS = libbackend.a

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

dnet_monitor_SOURCES = monitor.c
dnet_monitor_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_notify_SOURCES = notify.c
dnet_notify_LDADD = $(EXAMPLE_COMMON_LIBS)

if HAVE_FASTCGI
SUBDIRS += fcgi
endif

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @TOKYOCABINET_CFLAGS@ @EBLOB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @TOKYOCABINET_LIBS@ @EBLOB_LIBS@

EXTRA_DIST = EXAMPLE 00-INDEX ioserv.conf
