AC_DEFUN([AC_CHECK_EV],[
AC_LANG(C++)
AC_MSG_CHECKING([whether development version of libev is installed])
EV_LIBS="-lev"
ac_have_ev="no"

AC_ARG_WITH([ev-path],
	AC_HELP_STRING([--with-ev-path=@<:@ARG@:>@],
		[Build with the different path to ev (ARG=string)]),
	[
		EV_LIBS="-L$withval/lib -lev"
		# some packages use ev++.h, other libev/ev++.h as well as packages in various distros
		EV_CXXFLAGS="-I$withval/include -I$withval/include/libev"
	],
	[
		EV_CXXFLAGS="-I/usr/include/libev -I/usr/include"
	]
)

saved_CXXFLAGS="$CXXFLAGS"
saved_LIBS="$LIBS"
LIBS="$EV_LIBS $LIBS"
CXXFLAGS="$EV_CXXFLAGS $CXXFLAGS"

AC_TRY_LINK([#include <ev++.h>],
	[ev::tstamp ts;],
	[
		AC_DEFINE(HAVE_EV_SUPPORT, 1, [Define this if ev is installed])
		ac_have_ev="yes"
		AC_MSG_RESULT([yes])
	], [
		ac_have_ev="no"
		EV_LIBS=""
		EV_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(EV_LIBS)
AC_SUBST(EV_CXXFLAGS)
LIBS="$saved_LIBS"
CXXFLAGS="$saved_CXXFLAGS"
AM_CONDITIONAL(HAVE_EV, [test "f$ac_have_ev" = "fyes"])
])

