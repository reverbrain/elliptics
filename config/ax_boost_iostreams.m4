dnl @synopsis AX_BOOST_IOSTREAMS
dnl
dnl Test for IOStreams library from the Boost C++ libraries. The macro
dnl requires a preceding call to AX_BOOST_BASE. Further documentation
dnl is available at <http://randspringer.de/boost/index.html>.
dnl
dnl This macro calls:
dnl
dnl   AC_SUBST(BOOST_IOSTREAMS_LIB)
dnl
dnl And sets:
dnl
dnl   HAVE_BOOST_IOSTREAMS
dnl
dnl @category InstalledPackages
dnl @category Cxx
dnl @author Thomas Porschberg <thomas@randspringer.de>
dnl @version 2006-06-15
dnl @license AllPermissive

AC_DEFUN([AX_BOOST_IOSTREAMS],
[
	AC_ARG_WITH([boost-iostreams],
	AS_HELP_STRING([--with-boost-iostreams@<:@=special-lib@:>@],
                   [use the IOStreams library from boost - it is possible to specify a certain library for the linker
                        e.g. --with-boost-iostreams=boost_iostreams-gcc-mt-d-1_33_1 ]),
        [
        if test "$withval" = "no"; then
		want_boost="no"
        elif test "$withval" = "yes"; then
		want_boost="yes"
		ax_boost_user_iostreams_lib=""
        else
		want_boost="yes"
		ax_boost_user_iostreams_lib="$withval"
	fi
        ],
        [want_boost="yes"]
	)

	if test "x$want_boost" = "xyes"; then
        AC_REQUIRE([AC_PROG_CC])
		CPPFLAGS_SAVED="$CPPFLAGS"
		CPPFLAGS="$CPPFLAGS $BOOST_CPPFLAGS"
		export CPPFLAGS

		LDFLAGS_SAVED="$LDFLAGS"
		LDFLAGS="$LDFLAGS $BOOST_LDFLAGS"
		export LDFLAGS

        AC_CACHE_CHECK(whether the Boost::IOStreams library is available, ax_cv_boost_iostreams,
        [AC_LANG_PUSH([C++])
		 AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[@%:@include <boost/iostreams/filtering_stream.hpp>
 						     @%:@include <boost/range/iterator_range.hpp>]],
						   [[std::string  input = "Hello World!";
						     namespace io = boost::iostreams;
						     io::filtering_istream  in(boost::make_iterator_range(input));
						     return 0;
						   ]]),
						   ax_cv_boost_iostreams=yes, ax_cv_boost_iostreams=no)
		AC_LANG_POP([C++])])

	if test "x$ax_cv_boost_iostreams" = "xyes"; then
		AC_DEFINE(HAVE_BOOST_IOSTREAMS,,[define if the Boost::IOStreams library is available])
		BN=boost_iostreams
		if test "x$ax_boost_user_iostreams_lib" = "x"; then
			for ax_lib in $BN $BN-$CC $BN-$CC-mt $BN-$CC-mt-s $BN-$CC-s \
					lib$BN lib$BN-$CC lib$BN-$CC-mt lib$BN-$CC-mt-s lib$BN-$CC-s \
					$BN-mgw $BN-mgw $BN-mgw-mt $BN-mgw-mt-s $BN-mgw-s ; do
				AC_CHECK_LIB($ax_lib, main,
					[BOOST_IOSTREAMS_LIB="-l$ax_lib" AC_SUBST(BOOST_IOSTREAMS_LIB) link_thread="yes" break],
					[link_thread="no"])
			done
		else
			for ax_lib in $ax_boost_user_iostreams_lib $BN-$ax_boost_user_iostreams_lib; do
				AC_CHECK_LIB($ax_lib, main,
					[BOOST_IOSTREAMS_LIB="-l$ax_lib" AC_SUBST(BOOST_IOSTREAMS_LIB) link_iostreams="yes" break],
					[link_iostreams="no"])
			done
		fi
	fi

	CPPFLAGS="$CPPFLAGS_SAVED"
    	LDFLAGS="$LDFLAGS_SAVED"
	fi

	if test "x$link_iostreams" = "xyes"; then
		AM_CONDITIONAL([HAVE_BOOST_IOSTREAMS], [test "x$link_iostreams" = "xyes"])
	else
		AM_CONDITIONAL([HAVE_BOOST_IOSTREAMS], [test "x$link_thread" = "xyes"])
	fi
])
