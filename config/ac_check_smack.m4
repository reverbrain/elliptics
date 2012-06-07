AC_DEFUN([AC_CHECK_SMACK],[
AC_MSG_CHECKING([whether SMACK development version is installed])
SMACK_LIBS="-lsmack"
ac_have_smack="no"

AC_ARG_WITH([smack-path],
	AC_HELP_STRING([--with-smack-path=@<:@ARG@:>@],
		[Build with the different path to SMACK (ARG=string)]),
	[
		SMACK_LIBS="-L$withval/lib64 -L$withval/lib -lsmack -Wl,-rpath,$withval/lib64 -Wl,-rpath,$withval/lib"
		SMACK_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$SMACK_LIBS $LIBS"
CFLAGS="$SMACK_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <smack/smack.h>],
	[int err; struct smack_ctl *ctl = smack_init(NULL, &err);],
	[
		AC_DEFINE(HAVE_SMACK_SUPPORT, 1, [Define this if SMACK is installed])
		ac_have_smack="yes"
		AC_MSG_RESULT([yes])
	], [
		ac_have_smack="no"
		SMACK_LIBS=""
		SMACK_CFLAGS=""
		AC_MSG_RESULT([no])
	])

AC_SUBST(SMACK_LIBS)
AC_SUBST(SMACK_CFLAGS)
LIBS="$saved_LIBS"
CFLAGS="$saved_CFLAGS"
AM_CONDITIONAL(HAVE_SMACK, [test "f$ac_have_smack" = "fyes"])
])
