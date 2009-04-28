AC_DEFUN([AC_CHECK_TOKYOCABINET],[
AC_MSG_CHECKING([whether TokyoCabinet development version is installed])
TOKYOCABINET_LIBS="-ltokyocabinet"

AC_ARG_WITH([tokyocabinet-path],
	AC_HELP_STRING([--with-tokyocabinet-path=@<:@ARG@:>@],
		[Build with the different path to tokyocabinet (ARG=string)]),
	[
		TOKYOCABINET_LIBS="-L$withval/lib -ltokyocabinet"
		TOKYOCABINET_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$TOKYOCABINET_LIBS $LIBS"
CFLAGS="$TOKYOCABINET_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <tcadb.h>],
	[TCADB *adb = tcadbnew(); tcadbdel(adb);],
	[
		AC_DEFINE(HAVE_TOKYOCABINET_SUPPORT, 1, [Define this if TokyoCabinet is installed])
		AC_MSG_RESULT([yes])
	], [
		TOKYOCABINET_LIBS=""
		TOKYOCABINET_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(TOKYOCABINET_LIBS)
AC_SUBST(TOKYOCABINET_CFLAGS)
LIBS="$saved_LIBS"
])
