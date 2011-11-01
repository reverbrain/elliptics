AC_DEFUN([AC_CHECK_EBLOB],[
AC_MSG_CHECKING([whether libeblob development version is installed])
EBLOB_LIBS="-leblob"
ac_have_eblob="no"

AC_ARG_WITH([eblob-path],
	AC_HELP_STRING([--with-eblob-path=@<:@ARG@:>@],
		[Build with the different path to eblob (ARG=string)]),
	[
		EBLOB_LIBS="-L$withval/lib -leblob"
		EBLOB_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$EBLOB_LIBS $LIBS"
CFLAGS="$EBLOB_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <eblob/blob.h>],
	[struct eblob_backend *b = eblob_init(NULL);],
	[
		AC_DEFINE(HAVE_EBLOB_SUPPORT, 1, [Define this if libeblob is installed])
		ac_have_eblob="yes"
		AC_MSG_RESULT([yes])
	], [
		EBLOB_LIBS=""
		EBLOB_CFLAGS=""
		AC_MSG_ERROR([no])
	])

AC_SUBST(EBLOB_LIBS)
AC_SUBST(EBLOB_CFLAGS)
LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
AM_CONDITIONAL(HAVE_EBLOB, [test "f$ac_have_eblob" = "fyes"])
])
