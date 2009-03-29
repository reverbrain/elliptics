SUBDIRS = include library

if HAVE_OPENSSL
SUBDIRS += example
endif

ACLOCAL_AMFLAGS = -I config
AUTOMAKE_OPTIONS = 1.9 foreign

EXTRA_DIST = autogen.sh AUTHORS ChangeLog COPYING INSTALL NEWS README \
	config/acx_pthread.m4 config/ax_check_compiler_flags.m4 \
	config/ax_check_openssl.m4 config/ax_create_stdint_h.m4 \
	config/ax_prefix_config_h.m4 config/ac_c_bigendian_cross.m4 \
	config/ac_check_largefile.m4 config/ac_id_size.m4 \
	config/ac_check_sendfile.m4 config/ac_check_libevent.m4
