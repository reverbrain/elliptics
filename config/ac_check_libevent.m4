AC_DEFUN([AC_CHECK_LIBEVENT],[

EVENT_LIBS="-levent"
AC_ARG_WITH([libevent-path],
	AC_HELP_STRING([--with-libevent-path=@<:@ARG@:>@],
		[Build with the different path to libevent (ARG=string)]),
	[
		EVENT_LIBS="-L$withval/lib -levent"
		EVENT_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$EVENT_LIBS $LIBS"
CFLAGS="$EVENT_CFLAGS $CFLAGS"

AC_MSG_CHECKING([whether u_char is defined])
AC_TRY_LINK([	#include <unistd.h>
		#include <stdint.h>],
	[u_char test;],
	[
		ac_uchar_defined=yes
		AC_DEFINE(HAVE_UCHAR, 1, [Define this if u_char is supported])
	],
	[ac_uchar_defined=no])

AC_MSG_RESULT([$ac_uchar_defined])
AC_MSG_CHECKING([whether libevent is installed])

if test x$ac_uchar_defined = xyes; then
	CFLAGS="-DHAVE_UCHAR $CFLAGS"
fi

AC_TRY_LINK([	#include <unistd.h>
		#ifndef HAVE_UCHAR
		typedef unsigned char u_char;
		typedef unsigned short u_short;
		#endif
		#include <event.h>],
	[event_init(); event_dispatch();],
	[
		AC_MSG_RESULT([yes])
		AC_SUBST(EVENT_LIBS)
		AC_SUBST(EVENT_CFLAGS)
	
	],
	[
		AC_MSG_ERROR([no.

Please install libevent (http://monkey.org/~provos/libevent/) library
	or its development version from your distro])
	])

LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
])
