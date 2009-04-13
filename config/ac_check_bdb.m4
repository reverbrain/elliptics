AC_DEFUN([AC_CHECK_BDB],[
AC_MSG_CHECKING([whether BerkeleyDB development version is installed])
BDB_LIBS="-ldb"

AC_ARG_WITH([libdb-path],
	AC_HELP_STRING([--with-libdb-path=@<:@ARG@:>@],
		[Build with the different path to libdb (ARG=string)]),
	[
		BDB_LIBS="-L$withval/lib -ldb"
		BDB_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$BDB_LIBS $LIBS"
CFLAGS="$BDB_CFLAGS $CFLAGS"

AC_TRY_LINK([#include <db.h>],
	[DB *db; db_create(&db, NULL, 0);],
	[
		AC_DEFINE(HAVE_BDB_SUPPORT, 1, [Define this if BerkeleyDB is installed])
		AC_SUBST(BDB_LIBS)
		AC_SUBST(BDB_CFLAGS)
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

LIBS="$saved_LIBS"
])
