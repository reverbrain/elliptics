AC_DEFUN([AC_CHECK_LIBFCGI],[

FCGI_LIBS="-lfcgi"
AC_ARG_WITH([libfcgi-path],
	AC_HELP_STRING([--with-libfcgi-path=@<:@ARG@:>@],
		[Build with the different path to libfcgi (ARG=string)]),
	[
		FCGI_LIBS="-L$withval/lib -lfcgi"
		FCGI_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$FCGI_LIBS $LIBS"
CFLAGS="$FCGI_CFLAGS $CFLAGS"

AC_MSG_CHECKING([whether libfcgi is installed])

AC_TRY_LINK([#include <fcgi_stdio.h>],
	[FCGI_Accept();],
	[
		AC_MSG_RESULT([yes])
		AC_SUBST(FCGI_LIBS)
		AC_SUBST(FCGI_CFLAGS)
		AM_CONDITIONAL(HAVE_FASTCGI, true)
	],
	[
		AC_MSG_RESULT([no])
		AM_CONDITIONAL(HAVE_FASTCGI, false)
	])

LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
])
