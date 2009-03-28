AC_DEFUN([AC_CHECK_SENDFILE],[
AC_MSG_CHECKING([whether sendfile() is supported and what prototype it has])

ac_sendfile_supported=no
AC_TRY_LINK([#include <sys/sendfile.h>
		#include <stdio.h>],
	[sendfile(1, 1, NULL, 0);],
	[
		AC_DEFINE(HAVE_SENDFILE4_SUPPORT, 1,
			[Define this if Linux/Solaris sendfile() is supported])
		AC_MSG_RESULT([Linux sendfile()])
		ac_sendfile_supported=yes
	], [])

if test x$ac_sendfile_supported = xno; then
	dnl Checking wether we need libsendfile
	dnl Presumably on Solaris
	AC_CHECK_LIB(sendfile, sendfile,
		[
			AC_DEFINE(HAVE_SENDFILE4_SUPPORT, 1,
				[Define this if Linux/Solaris sendfile() is supported])
			SENDFILE_LIBS="-lsendfile"
			AC_SUBST(SENDFILE_LIBS)
			AC_MSG_RESULT([Solaris sendfile()])
			ac_sendfile_supported=yes
		], [])
fi

if test x$ac_sendfile_supported = xno; then
	dnl Checking wether we have FreeBSD-like sendfile() support.
	AC_TRY_LINK([#include <sys/socket.h>
			#include <stdio.h>],
		[sendfile(1, 1, 0, 0, NULL, NULL, 0);],
		[
			AC_DEFINE(HAVE_SENDFILE7_SUPPORT, 1,
				[Define this if FreeBSD sendfile() is supported])
			AC_MSG_RESULT([FreeBSD sendfile()])
			ac_sendfile_supported=yes
		], [])
fi

if test x$ac_sendfile_supported = xno; then
	AC_MSG_ERROR([no sendfile support])
fi
])
