bin_PROGRAMS = example hparser iotest
noinst_LIBRARIES = libhash.a
noinst_HEADERS = hash.h backends.h

CC = @PTHREAD_CC@

libhash_a_SOURCES = hash.c lookup3.c

example_SOURCES = example.c file_backend.c bdb_backend.c
example_LDADD = ../library/libdnet.la libhash.a

hparser_SOURCES = hparser.c
hparser_LDADD = ../library/libdnet.la

iotest_SOURCES = iotest.c hash.c
iotest_LDADD = ../library/libdnet.la libhash.a

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @BDB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BDB_LIBS@

EXTRA_DIST = EXAMPLE
