AC_DEFUN([AC_CHECK_KYOTOCABINET],[
AC_MSG_CHECKING([whether Kyoto Cabinet DB development version is installed])
KYOTOCABINET_LIBS="-lkyotocabinet"
ac_have_kyotocabinet="no"

AC_ARG_WITH([kyotocabinet-path],
	AC_HELP_STRING([--with-kyotocabinet-path=@<:@ARG@:>@],
		[Build with the different path to Kyoto Cabinet (ARG=string)]),
	[
		KYOTOCABINET_LIBS="-L$withval/lib -lkyotocabinet"
		KYOTOCABINET_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$KYOTOCABINET_LIBS $LIBS"
CFLAGS="$KYOTOCABINET_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <kclangc.h>],
	[KCDB *db = kcdbnew(); kcdbdel(db);],
	[
		AC_DEFINE(HAVE_KYOTOCABINET_SUPPORT, 1, [Define this if Kyoto Cabinet is installed])
		ac_have_kyotocabinet="yes"
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_ERROR([Kyoto Cabinet was not found. Please install library from http://fallabs.com/kyotocabinet/])
	])

AC_SUBST(KYOTOCABINET_LIBS)
AC_SUBST(KYOTOCABINET_CFLAGS)
LIBS="$saved_LIBS"
AM_CONDITIONAL(HAVE_KYOTOCABINET, [test "f$ac_have_kyotocabinet" = "fyes"])
])
