lib_LTLIBRARIES = libelliptics.la

CC = @PTHREAD_CC@
AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @ATOMIC_CFLAGS@ @EBLOB_CFLAGS@

ELLIPTICS_LDFLAGS = @PTHREAD_LIBS@ @SENDFILE_LIBS@ @ATOMIC_LIBS@ @VERSION_INFO@ @EBLOB_LIBS@ \
		    libelliptics_cocaine.so @COCAINE_LIBS@ @MSGPACK_LIBS@ @ZMQ_LIBS@

libelliptics_la_SOURCES = dnet.c log.c net.c node.c rbtree.c trans.c compat.c \
			  notify.c meta.c metadb.c crypto.c check.c \
			  pool.c crypto/sha512.c locks.c
libelliptics_la_LIBADD = ../srw/libelliptics_cocaine.la

noinst_HEADERS = elliptics.h list.h rbtree.h atomic.h lock.h crypto/u64.h crypto/sha512.h

AM_LDFLAGS = ${ELLIPTICS_LDFLAGS}
