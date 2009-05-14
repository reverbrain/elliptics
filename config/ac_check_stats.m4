AC_DEFUN([AC_CHECK_STAT],[
AC_MSG_CHECKING([supported method to gather system statistics])

ac_stat_support=no
if test -f "/proc/loadavg"; then
	if test -f "/proc/meminfo"; then
		ac_stat_support="/proc"
		AC_DEFINE(HAVE_PROC_STAT, 1, [Define this if system supports procfs statistics])
	fi
fi

if test $ac_stat_support = no; then
AC_TRY_RUN([#include <stdio.h>
		#include <sys/types.h>
		#include <sys/sysctl.h>
		#include <sys/resource.h>
		int main ()
		{
			struct loadavg la;
			size_t sz = sizeof(la);
			return sysctlbyname("vm.loadavg", &la, &sz, NULL, 0);
		}
	],
	[
		ac_stat_support=sysctl
		AC_DEFINE(HAVE_SYSCTL_STAT, 1, [Define this if system supports sysctl statistics])
	]
)
fi

AC_MSG_RESULT([$ac_stat_support])
])
