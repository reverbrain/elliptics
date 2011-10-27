AC_DEFUN([AC_CHECK_SRW],[
AC_MSG_CHECKING([whether libsrw development version is installed])
SRW_LIBS="-lsrw"
ac_have_srw="no"

AC_ARG_WITH([srw-path],
	AC_HELP_STRING([--with-srw-path=@<:@ARG@:>@],
		[Build with the different path to srw (ARG=string)]),
	[
		SRW_LIBS="-L$withval/lib -lsrw"
		SRW_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$SRW_LIBS $LIBS"
CFLAGS="$SRW_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <srw/srwc.h>],
	[struct srwc *c = srwc_init_python("", "", 5, "qwe", 3, NULL);],
	[
		AC_DEFINE(HAVE_SRW_SUPPORT, 1, [Define this if libsrw is installed])
		ac_have_srw="yes"
		AC_MSG_RESULT([yes])
	], [
		SRW_LIBS=""
		SRW_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(SRW_LIBS)
AC_SUBST(SRW_CFLAGS)
LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
AM_CONDITIONAL(HAVE_SRW, [test "f$ac_have_srw" = "fyes"])
])
