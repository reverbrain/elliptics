lib_LTLIBRARIES = libdnet.la

CC = @PTHREAD_CC@

libdnet_la_SOURCES = dnet.c history.c log.c net.c node.c rbtree.c trans.c compat.c

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@

noinst_HEADERS = elliptics.h list.h rbtree.h trans.h
