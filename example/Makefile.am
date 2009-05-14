bin_PROGRAMS = example hparser iotest stat
noinst_LIBRARIES = libhash.a
noinst_HEADERS = hash.h backends.h

CC = @PTHREAD_CC@

libhash_a_SOURCES = hash.c lookup3.c

example_SOURCES = example.c file_backend.c bdb_backend.c tc_backend.c backends.c
example_LDADD = ../library/libdnet.la libhash.a

hparser_SOURCES = hparser.c
hparser_LDADD = ../library/libdnet.la

iotest_SOURCES = iotest.c hash.c
iotest_LDADD = ../library/libdnet.la libhash.a

stat_SOURCES = stat.c
stat_LDADD = ../library/libdnet.la

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @BDB_CFLAGS@ \
	@TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BDB_LIBS@ \
	@TOKYOCABINET_LIBS@

EXTRA_DIST = EXAMPLE
