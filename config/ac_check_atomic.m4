AC_DEFUN([AC_CHECK_ATOMIC],[
AC_MSG_CHECKING([whether libatomic or __sync are supported])
ATOMIC_LIBS="-latomic"

AC_ARG_WITH([libatomic-path],
	AC_HELP_STRING([--with-libatomic-path=@<:@ARG@:>@],
		[Build with the different path to libatomic (ARG=string)]),
	[
		ATOMIC_LIBS="-L$withval/lib -latomic"
		ATOMIC_CFLAGS="-I$withval/include"
	]
)

saved_CFLAGS="$CFLAGS"
saved_LIBS="$LIBS"
LIBS="$ATOMIC_LIBS $LIBS"
CFLAGS="$ATOMIC_CFLAGS $CFLAGS -Werror-implicit-function-declaration"

ac_atomic_support=no
AC_TRY_LINK([#include <atomic/atomic.h>],
	[atomic_t a; atomic_set(&a, 1); atomic_inc(&a);],
	[
		AC_DEFINE(HAVE_LIBATOMIC_SUPPORT, 1, [Define this if libatomic is installed])
		ac_atomic_support=libatomic
	], [
		ATOMIC_LIBS=""
		ATOMIC_CFLAGS=""
	]
)

AC_SUBST(ATOMIC_LIBS)
AC_SUBST(ATOMIC_CFLAGS)
LIBS="$saved_LIBS"

if test x$ac_atomic_support = xno; then
AC_TRY_LINK([],
	[long var; __sync_add_and_fetch(&var, 1)],
	[
		AC_DEFINE(HAVE_SYNC_ATOMIC_SUPPORT, 1, [Define this if __sync calls are supported])
		ac_atomic_support=__sync
	], []
)
fi

AC_MSG_RESULT([$ac_atomic_support])

CFLAGS="$saved_CFLAGS"
])
