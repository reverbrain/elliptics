noinst_PROGRAMS = example

CC = @PTHREAD_CC@

example_SOURCES = example.c
example_LDADD = ../library/libdnet.la

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@

EXTRA_DIST = EXAMPLE
