bin_PROGRAMS = dnet_fcgi

dnet_fcgi_SOURCES = fcgi.c
dnet_fcgi_LDADD = ../libcommon.a ../libhash.a ../../library/libdnet.la

CC = @PTHREAD_CC@
AM_CFLAGS = -I../../include -I../ -I../../config @FCGI_CFLAGS@ @OPENSSL_CFLAGS@ @PTHREAD_CFLAGS@
AM_LDFLAGS = @FCGI_LIBS@ @OPENSSL_LIBS@ @PTHREAD_LIBS@
EXTRA_DIST = lighttpd-fastcgi-dnet.conf README
