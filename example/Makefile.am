bin_PROGRAMS = dnet_ioserv dnet_hparser dnet_iotest dnet_stat dnet_notify
noinst_LIBRARIES = libhash.a libcommon.a libbackend.a
noinst_HEADERS = hash.h backends.h common.h
SUBDIRS = .

CC = @PTHREAD_CC@

libhash_a_SOURCES = hash.c lookup3.c
libcommon_a_SOURCES = common.c
libbackend_a_SOURCES = file_backend.c bdb_backend.c tc_backend.c backends.c

dnet_ioserv_SOURCES = ioserv.c
dnet_ioserv_LDADD = ../library/libdnet.la libhash.a libcommon.a libbackend.a

dnet_hparser_SOURCES = hparser.c
dnet_hparser_LDADD = ../library/libdnet.la

dnet_iotest_SOURCES = iotest.c
dnet_iotest_LDADD = ../library/libdnet.la libhash.a libcommon.a

dnet_stat_SOURCES = stat.c
dnet_stat_LDADD = ../library/libdnet.la libcommon.a

dnet_notify_SOURCES = notify.c
dnet_notify_LDADD = ../library/libdnet.la libcommon.a

if HAVE_FASTCGI
SUBDIRS += fcgi
endif

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @BDB_CFLAGS@ \
	@TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BDB_LIBS@ \
	@TOKYOCABINET_LIBS@

EXTRA_DIST = EXAMPLE 00-INDEX
