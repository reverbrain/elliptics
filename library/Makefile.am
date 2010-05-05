lib_LTLIBRARIES = libdnet.la

CC = @PTHREAD_CC@

libdnet_la_SOURCES = dnet.c log.c net.c node.c rbtree.c trans.c compat.c notify.c meta.c

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @EVENT_CFLAGS@ @ATOMIC_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @SENDFILE_LIBS@ @EVENT_LIBS@ @ATOMIC_LIBS@

noinst_HEADERS = elliptics.h list.h rbtree.h atomic.h lock.h
