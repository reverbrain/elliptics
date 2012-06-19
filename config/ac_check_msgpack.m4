AC_DEFUN([AC_CHECK_MSGPACK],[
AC_LANG(C++)
AC_MSG_CHECKING([whether development version of msgpack ( http:// msgpack.org ) library is installed])
MSGPACK_LIBS="-lmsgpack"
ac_have_msgpack="no"

AC_ARG_WITH([msgpack-path],
	AC_HELP_STRING([--with-msgpack-path=@<:@ARG@:>@],
		[Build with the different path to msgpack (ARG=string)]),
	[
		MSGPACK_LIBS="-L$withval/lib -lmsgpack"
		MSGPACK_CXXFLAGS="-I$withval/include"
	]
)

saved_CXXFLAGS="$CXXFLAGS"
saved_LIBS="$LIBS"
LIBS="$MSGPACK_LIBS $LIBS"
CXXFLAGS="$MSGPACK_CXXFLAGS $CXXFLAGS"

AC_TRY_LINK([#include <msgpack.hpp>],
	[msgpack::sbuffer buffer;],
	[
		AC_DEFINE(HAVE_MSGPACK_SUPPORT, 1, [Define this if msgpack is installed])
		ac_have_msgpack="yes"
		AC_MSG_RESULT([yes])
	], [
		ac_have_msgpack="no"
		MSGPACK_LIBS=""
		MSGPACK_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(MSGPACK_LIBS)
AC_SUBST(MSGPACK_CXXFLAGS)
LIBS="$saved_LIBS"
CXXFLAGS="$saved_CXXFLAGS"
AM_CONDITIONAL(HAVE_MSGPACK, [test "f$ac_have_msgpack" = "fyes"])
])
