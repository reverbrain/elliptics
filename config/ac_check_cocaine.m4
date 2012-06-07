AC_DEFUN([AC_CHECK_COCAINE],[
AC_LANG(C++)
AC_MSG_CHECKING([whether development version of cocaine ( https://github.com/cocaine/cocaine-core ) engine library is installed])
COCAINE_LIBS="-lcocaine-core -lcocaine-common"
ac_have_cocaine="no"

AC_ARG_WITH([cocaine-path],
	AC_HELP_STRING([--with-cocaine-path=@<:@ARG@:>@],
		[Build with the different path to cocaine (ARG=string)]),
	[
		COCAINE_LIBS="-L$withval/lib -lcocaine-core -lcocaine-common"
		COCAINE_CXXFLAGS="-I$withval/include"
	]
)

saved_CXXFLAGS="$CXXFLAGS"
saved_LIBS="$LIBS"
LIBS="$COCAINE_LIBS $LIBS"
CXXFLAGS="$COCAINE_CXXFLAGS $CXXFLAGS"

AC_TRY_LINK([#include <cocaine/context.hpp>],
	[cocaine::config_t config("/tmp/test");],
	[
		AC_DEFINE(HAVE_COCAINE_SUPPORT, 1, [Define this if cocaine is installed])
		ac_have_cocaine="yes"
		AC_MSG_RESULT([yes])
	], [
		ac_have_cocaine="no"
		COCAINE_LIBS=""
		COCAINE_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(COCAINE_LIBS)
AC_SUBST(COCAINE_CXXFLAGS)
LIBS="$saved_LIBS"
CXXFLAGS="$saved_CXXFLAGS"
AM_CONDITIONAL(HAVE_COCAINE, [test "f$ac_have_cocaine" = "fyes"])
])
