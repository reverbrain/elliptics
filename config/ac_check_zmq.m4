AC_DEFUN([AC_CHECK_ZMQ],[
AC_LANG(C++)
AC_MSG_CHECKING([whether development version of zmq ( http://zeromq.org ) library is installed])
ZMQ_LIBS="-lzmq"
ac_have_zmq="no"

AC_ARG_WITH([zmq-path],
	AC_HELP_STRING([--with-zmq-path=@<:@ARG@:>@],
		[Build with the different path to zmq (ARG=string)]),
	[
		ZMQ_LIBS="-L$withval/lib -lzmq"
		ZMQ_CXXFLAGS="-I$withval/include"
	]
)

saved_CXXFLAGS="$CXXFLAGS"
saved_LIBS="$LIBS"
LIBS="$ZMQ_LIBS $LIBS"
CXXFLAGS="$ZMQ_CXXFLAGS $CXXFLAGS"

AC_TRY_LINK([#include <zmq.hpp>],
	[zmq::message_t message; int a = ZMQ_RCVTIMEO;],
	[
		AC_DEFINE(HAVE_ZMQ_SUPPORT, 1, [Define this if zmq is installed])
		ac_have_zmq="yes"
		AC_MSG_RESULT([yes])
	], [
		ac_have_zmq="no"
		ZMQ_LIBS=""
		ZMQ_CFLAGS=""
		AC_MSG_RESULT([no (you need at least 2.2.0 version)])
	])

AC_SUBST(ZMQ_LIBS)
AC_SUBST(ZMQ_CXXFLAGS)
LIBS="$saved_LIBS"
CXXFLAGS="$saved_CXXFLAGS"
AM_CONDITIONAL(HAVE_ZMQ, [test "f$ac_have_zmq" = "fyes"])
])
