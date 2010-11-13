lib_LTLIBRARIES = libelliptics.la

CC = @PTHREAD_CC@

libelliptics_la_SOURCES = dnet.c log.c net.c node.c rbtree.c trans.c compat.c notify.c meta.c history.c

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @ATOMIC_CFLAGS@ @BDB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @SENDFILE_LIBS@ @ATOMIC_LIBS@ @BDB_LIBS@

noinst_HEADERS = elliptics.h list.h rbtree.h atomic.h lock.h
