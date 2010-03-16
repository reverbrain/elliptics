bin_PROGRAMS = dnet_check_log dnet_check_merge
noinst_LIBRARIES = libcheck.a
noinst_HEADERS = common.h

CHECK_COMMON_LIBS = libcheck.a ../../library/libdnet.la ../libhash.a ../libcommon.a

libcheck_a_SOURCES = common.c

dnet_check_log_SOURCES = log.c
dnet_check_log_LDADD = $(CHECK_COMMON_LIBS)

dnet_check_merge_SOURCES = merge.c
dnet_check_merge_LDADD = $(CHECK_COMMON_LIBS)

CC = @PTHREAD_CC@
AM_CFLAGS = -I../../include -I../../config @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @TOKYOCABINET_LIBS@
