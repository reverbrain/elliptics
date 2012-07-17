bin_PROGRAMS = dnet_ioserv dnet_hparser dnet_stat dnet_notify dnet_ioclient dnet_check dnet_ids dnet_meta dnet_meta_update_groups dnet_find
noinst_LIBRARIES = libcommon.a
noinst_HEADERS = backends.h common.h
SUBDIRS = .
EXTRA_DIST = EXAMPLE 00-INDEX ioserv.conf example/library_config.json

CC = @PTHREAD_CC@

AM_CFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@
AM_CXXFLAGS = -I../include -I../config @PTHREAD_CFLAGS@ @EBLOB_CFLAGS@

AM_LDFLAGS = @PTHREAD_LIBS@ @EBLOB_LIBS@


EXAMPLE_COMMON_LIBS =  libcommon.a ../library/libelliptics.la ../srw/libelliptics_cocaine.la

libcommon_a_SOURCES = common.c

dnet_ioserv_SOURCES = ioserv.c config.c file_backend.c backends.c eblob_backend.c
dnet_ioserv_LDADD = $(EXAMPLE_COMMON_LIBS) @EBLOB_LIBS@
if HAVE_SMACK
AM_CFLAGS += @SMACK_CFLAGS@
dnet_ioserv_SOURCES += smack_backend.c
dnet_ioserv_LDADD += @SMACK_LIBS@
endif

dnet_check_SOURCES = check.c
dnet_check_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_find_SOURCES = find.cpp
dnet_find_LDADD = $(EXAMPLE_COMMON_LIBS) ../bindings/cpp/libelliptics_cpp.la

dnet_meta_SOURCES = meta.c
dnet_meta_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_ioclient_SOURCES = ioclient.c
dnet_ioclient_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_hparser_SOURCES = hparser.c
dnet_hparser_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_stat_SOURCES = stat.c
dnet_stat_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_notify_SOURCES = notify.c
dnet_notify_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_meta_update_groups_SOURCES = meta_update_groups.c
dnet_meta_update_groups_LDADD = $(EXAMPLE_COMMON_LIBS)

dnet_ids_SOURCES = ids.c
