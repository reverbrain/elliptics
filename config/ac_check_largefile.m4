AC_DEFUN([AC_CHECK_LARGEFILE],[
AC_MSG_CHECKING([whether O_LARGEFILE is supported])
AC_TRY_LINK([#include <fcntl.h>
	#include <sys/stat.h>],
	[int fd = open(".", O_RDONLY | O_LARGEFILE);],
	[ac_largefile_supported=yes],
	[ac_largefile_supported=no])

AC_MSG_RESULT([$ac_largefile_supported])

if test x$ac_largefile_supported = xyes; then
	AC_DEFINE(HAVE_LARGEFILE_SUPPORT, 1, [Define this if O_LARGEFILE is supported])
fi

])
