lib_LTLIBRARIES = libelliptics.la

CC = @PTHREAD_CC@

libelliptics_la_SOURCES = dnet.c log.c net.c node.c rbtree.c trans.c compat.c \
			  notify.c meta.c metadb.c crypto.c check.c \
			  pool.c crypto/sha512.c srw.c locks.c
libelliptics_la_LIBADD = ../srw/src/libsrw.la

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @ATOMIC_CFLAGS@ @EBLOB_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @SENDFILE_LIBS@ @ATOMIC_LIBS@ @VERSION_INFO@ @EBLOB_LIBS@

noinst_HEADERS = elliptics.h list.h rbtree.h atomic.h lock.h crypto/u64.h crypto/sha512.h

AM_CFLAGS += -DELLIPTICS_GIT_VERSION=\"$(shell test -d ../.git && git show-ref --hash refs/heads/master)\" \
	     -DELLIPTICS_HAS_CHANGES=\"$(shell git status --porcelain --untracked-files=no | wc -l)\"
