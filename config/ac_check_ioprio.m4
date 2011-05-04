AC_DEFUN([AC_CHECK_IOPRIO],[
AC_MSG_CHECKING([whether ioprio_* are supported])
AC_TRY_LINK([#include <sys/types.h>
	#include <unistd.h>
	#include <sys/syscall.h>],
	[syscall(SYS_ioprio_set, 1, getpid(), 3);
	int prio = syscall(SYS_ioprio_get, 1, getpid());],
	[ac_ioprio_supported=yes],
	[ac_ioprio_supported=no])

AC_MSG_RESULT([$ac_ioprio_supported])

if test x$ac_ioprio_supported = xyes; then
	AC_DEFINE(HAVE_IOPRIO_SUPPORT, 1, [Define this if ioprio_* are supported])
fi

])
