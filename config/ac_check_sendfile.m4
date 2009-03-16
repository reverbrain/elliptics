AC_DEFUN([AC_CHECK_SENDFILE],[
AC_MSG_CHECKING([whether sendfile() is supported and what prototype it has])

AC_CACHE_VAL([ac_sendfile4_supported],[
	AC_TRY_LINK([#include <sys/sendfile.h>
			#include <stdio.h>],
		[sendfile(1, 1, NULL, 0);],
		[
			ac_sendfile4_supported=yes
			ac_sendfile_supported=yes
			AC_MSG_RESULT([usual Linux/Solaris sendfile()])
		],
		[
			dnl Checking wether we need libsendfile
			dnl Presumably on Solaris
			AC_CHECK_LIB(sendfile, sendfile,
				[
					ac_sendfile4_supported=yes
					ac_sendfile_supported=yes
					SENDFILE_LIBS="-lsendfile"
					AC_SUBST(SENDFILE_LIBS)
				],
				[ac_sendfile_supported=no])
		])
])

if test x$ac_sendfile_supported = xno; then
	AC_CACHE_VAL([ac_sendfile7_supported],[
		AC_TRY_LINK([#include <sys/socket.h>
				#include <stdio.h>],
			[sendfile(1, 1, 0, 0, NULL, NULL, 0);],
			[
				ac_sendfile7_supported=yes
				ac_sendfile_supported=yes
				AC_MSG_RESULT([ugly FreeBSD sendfile()])
			],
			[ac_sendfile_supported=no])
	])
fi

if test x$ac_sendfile_supported = xno; then
	AC_MSG_ERROR([no sendfile support])
fi

if test x$ac_sendfile4_supported = xyes; then
	AC_DEFINE(HAVE_SENDFILE4_SUPPORT, 1, [Define this if Linux/Solaris sendfile() is supported])
fi

if test x$ac_sendfile7_supported = xyes; then
	AC_DEFINE(HAVE_SENDFILE7_SUPPORT, 1, [Define this if FreeBSD sendfile() is supported])
fi

])

