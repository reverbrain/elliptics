# SYNOPSIS
#
#   AG_CHECK_AT_SYSCALLS
#
# DESCRIPTION
#
#   Check that the POSIX (not yet released revision as of March 2009) compliant
#   mkdirat(2) and renameat(2) calls work properly or can be emulated via procfs.
#
# LAST MODIFICATION
#
#   2009-03-15
#
# COPYLEFT
#
#   Copyright (c) 2009 Evgeniy Polyakov <zbr@ioremap.net>
#   Based on the AG_CHECK_UNAME_SYSCALL script by Bruce Korb <bkorb@gnu.org>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.

AC_DEFUN([AG_CHECK_AT_SYSCALLS],[
AC_MSG_CHECKING([whether mkdirat(2) and renameat(2) are imlemented])
AC_CACHE_VAL([ag_cv_at_syscalls],[
	AC_TRY_LINK([#define _ATFILE_SOURCE
		#include <fcntl.h>
		#include <sys/stat.h>],
		[mkdirat(-1, ".", 0755); renameat(-1, ".", -1, ".");],
		[ag_cv_at_syscalls=yes],
		[ag_cv_at_syscalls=no])
])

AC_MSG_RESULT([$ag_cv_at_syscalls])

if test x$ag_cv_at_syscalls = xyes; then
	AC_DEFINE(HAVE_AT_SYSCALLS, 1, [Define this if mkdirat(2) and renameat() are supported])
fi

])
