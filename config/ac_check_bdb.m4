AC_DEFUN([AC_CHECK_BDB],[
AC_MSG_CHECKING([whether BerkeleyDB development version is installed])
saved_LIBS="$LIBS"
LIBS="-ldb $LIBS"

AC_TRY_LINK([#include <db.h>],
	[DB *db; db_create(&db, NULL, 0);],
	[
		AC_DEFINE(HAVE_BDB_SUPPORT, 1, [Define this if BerkeleyDB is installed])
		BDB_LIBS="-ldb"
		AC_SUBST(BDB_LIBS)
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

LIBS="$saved_LIBS"
])
