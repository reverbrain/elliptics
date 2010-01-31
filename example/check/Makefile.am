bin_PROGRAMS = dnet_check_log

CHECK_COMMON_LIBS = ../../library/libdnet.la ../libhash.a ../libcommon.a

dnet_check_log_SOURCES = log.c
dnet_check_log_LDADD = $(CHECK_COMMON_LIBS)

CC = @PTHREAD_CC@
AM_CFLAGS = -I../../include -I../../config -I../ @PTHREAD_CFLAGS@ @OPENSSL_CFLAGS@ @BDB_CFLAGS@ \
	@TOKYOCABINET_CFLAGS@
AM_LDFLAGS = @PTHREAD_LIBS@ @OPENSSL_LIBS@ @OPENSSL_LDFLAGS@ @BDB_LIBS@ \
	@TOKYOCABINET_LIBS@
