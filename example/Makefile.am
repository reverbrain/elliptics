bin_PROGRAMS = example hparser iotest stat
noinst_LIBRARIES = libhash.a libcommon.a libbackend.a
noinst_HEADERS = hash.h backends.h common.h

CC = @PTHREAD_CC@

libhash_a_SOURCES = hash.c lookup3.c
libcommon_a_SOURCES = common.c
libbackend_a_SOURCES = file_backend.c bdb_backend.c tc_backend.c backends.c

example_SOURCES = example.c
example_LDADD = ../library/libdnet.la libhash.a libcommon.a libbackend.a

hparser_SOURCES = hparser.c
hparser_LDADD = ../library/libdnet.la

iotest_SOURCES = iotest.c
iotest_LDADD = ../library/libdnet.la libhash.a libcommon.a

stat_SOURCES = stat.c
stat_LDADD = ../library/libdnet.la libcommon.a

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @BDB_CFLAGS@ \
	@TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BDB_LIBS@ \
	@TOKYOCABINET_LIBS@

EXTRA_DIST = EXAMPLE
