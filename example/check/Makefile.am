bin_PROGRAMS = dnet_check_log dnet_check_merge dnet_check_create
noinst_LIBRARIES = libcheck.a
noinst_HEADERS = common.h

CHECK_COMMON_LIBS = libcheck.a ../../library/libelliptics.la ../libcommon.a

libcheck_a_SOURCES = common.c

dnet_check_create_SOURCES = create.c
dnet_check_create_LDADD = $(CHECK_COMMON_LIBS)

dnet_check_log_SOURCES = log.c
dnet_check_log_LDADD = $(CHECK_COMMON_LIBS)

dnet_check_merge_SOURCES = merge.c
dnet_check_merge_LDADD = $(CHECK_COMMON_LIBS)

CC = @PTHREAD_CC@
AM_CFLAGS = -I../../include -I../../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@

EXTRA_DIST = README.check
