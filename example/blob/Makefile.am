bin_PROGRAMS = dnet_blob_check
pkginclude_HEADERS = blob.h
lib_LTLIBRARIES = libelliptics_blob.la
noinst_LIBRARIES = libblob_backend.a

libelliptics_blob_la_SOURCES = iter.c

libblob_backend_a_SOURCES = backend.c
libblob_backend_a_LIBADD = iter.o

dnet_blob_check_SOURCES = check.c

CC = @PTHREAD_CC@
AM_CFLAGS = -I../../include -I../ -I../../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@
