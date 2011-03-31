dnl @synopsis AX_BOOST_PROGRAM_OPTIONS
dnl
dnl Test for program options library from the Boost C++ libraries. The
dnl macro requires a preceding call to AX_BOOST_BASE. Further
dnl documentation is available at
dnl <http://randspringer.de/boost/index.html>.
dnl
dnl This macro calls:
dnl
dnl   AC_SUBST(BOOST_PROGRAM_OPTIONS_LIB)
dnl
dnl And sets:
dnl
dnl   HAVE_BOOST_PROGRAM_OPTIONS
dnl
dnl @category InstalledPackages
dnl @category Cxx
dnl @author Thomas Porschberg <thomas@randspringer.de>
dnl @version 2006-06-15
dnl @license AllPermissive

AC_DEFUN([AX_BOOST_PROGRAM_OPTIONS],
[
	AC_ARG_WITH([boost-program-options],
		AS_HELP_STRING([--with-boost-program-options@<:@=special-lib@:>@],
                       [use the program options library from boost - it is possible to specify a certain library for the linker
                        e.g. --with-boost-program-options=boost_program_options-gcc-mt-1_33_1 ]),
        [
        if test "$withval" = "no"; then
		want_boost="no"
        elif test "$withval" = "yes"; then
		want_boost="yes"
		ax_boost_user_program_options_lib=""
        else
		want_boost="yes"
        	ax_boost_user_program_options_lib="$withval"
	fi
        ],
        [want_boost="yes"]
	)

	if test "x$want_boost" = "xyes"; then
        AC_REQUIRE([AC_PROG_CC])
	    export want_boost
		CPPFLAGS_SAVED="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
		export CPPFLAGS
		LDFLAGS_SAVED="$LDFLAGS"
		LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"
		export LDFLAGS
		AC_CACHE_CHECK([whether the Boost::Program_Options library is available],
					   ax_cv_boost_program_options,
					   [AC_LANG_PUSH(C++)
 		                AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[@%:@include <boost/program_options.hpp>
                                                          ]],
                                  [[boost::program_options::options_description generic("Generic options");
                                   return 0;]]),
                           ax_cv_boost_program_options=yes, ax_cv_boost_program_options=no)
			               	AC_LANG_POP([C++])
		])
		if test "$ax_cv_boost_program_options" = yes; then
				AC_DEFINE(HAVE_BOOST_PROGRAM_OPTIONS,,[define if the Boost::PROGRAM_OPTIONS library is available])
				  BN=boost_program_options
			if test "x$ax_boost_user_program_options_lib" = "x"; then
					  for ax_lib in $BN $BN-$CC $BN-$CC-mt $BN-$CC-mt-s $BN-$CC-s \
					lib$BN lib$BN-$CC lib$BN-$CC-mt lib$BN-$CC-mt-s lib$BN-$CC-s \
					$BN-mgw $BN-mgw $BN-mgw-mt $BN-mgw-mt-s $BN-mgw-s ; do
					      AC_CHECK_LIB($ax_lib, main,
					   [BOOST_PROGRAM_OPTIONS_LIB="-l$ax_lib" AC_SUBST(BOOST_PROGRAM_OPTIONS_LIB) link_program_options="yes" break],
					   [link_program_options="no"])
					  done
			else
			  for ax_lib in $ax_boost_user_program_options_lib $BN-$ax_boost_user_program_options_lib; do
					      AC_CHECK_LIB($ax_lib, main,
					   [BOOST_PROGRAM_OPTIONS_LIB="-l$ax_lib" AC_SUBST(BOOST_PROGRAM_OPTIONS_LIB) link_program_options="yes" break],
					   [link_program_options="no"])
			  done
			fi
		fi

		CPPFLAGS="$CPPFLAGS_SAVED"
	    	LDFLAGS="$LDFLAGS_SAVED"
	fi

	AM_CONDITIONAL([HAVE_BOOST_PROGRAM_OPTIONS], [test "x$link_program_options" = "xyes"])
])
