AC_DEFUN([AX_SET_VERSION_INFO],[dnl
AS_VAR_PUSHDEF([MAJOR],ifelse($2,,[MAJOR_VERSION],[$2_MAJOR_VERSION]))dnl
AS_VAR_PUSHDEF([MINOR],ifelse($2,,[MINOR_VERSION],[$2_MINOR_VERSION]))dnl
AS_VAR_PUSHDEF([MICRO],ifelse($2,,[MICRO_VERSION],[$2_MICRO_VERSION]))dnl
AS_VAR_PUSHDEF([PATCH],ifelse($2,,[PATCH_VERSION],[$2_PATCH_VERSION]))dnl
AS_VAR_PUSHDEF([LTREL],ifelse($2,,[RELEASE_INFO],[$2_RELEASE_INFO]))dnl
AS_VAR_PUSHDEF([LTVER],ifelse($2,,[VERSION_INFO],[$2_VERSION_INFO]))dnl
  test ".$PACKAGE_VERSION" = "." && PACKAGE_VERSION="$VERSION"
  AC_MSG_CHECKING(ifelse($2,,,[$2 ])out linker version info dnl
  ifelse($1,,$PACKAGE_VERSION,$1) )
  MINOR=`echo ifelse( $1, , $PACKAGE_VERSION, $1 )`
  MAJOR=`echo "$MINOR" | sed -e 's/[[.]].*//'`
  MINOR=`echo "$MINOR" | sed -e "s/^$MAJOR//" -e 's/^.//'`
  MICRO="$MINOR"
  MINOR=`echo "$MICRO" | sed -e 's/[[.]].*//'`
  MICRO=`echo "$MICRO" | sed -e "s/^$MINOR//" -e 's/^.//'`
  PATCH="$MICRO"
  MICRO=`echo "$PATCH" | sed -e 's/[[^0-9]].*//'`
  PATCH=`echo "$PATCH" | sed -e "s/^$MICRO//" -e 's/[[-.]]//'`
  if test "_$MICRO" = "_" ; then MICRO="0" ; fi
  if test "_$MINOR" = "_" ; then MINOR="$MAJOR" ; MAJOR="0" ; fi
  MINOR=`echo "$MINOR" | sed -e 's/[[^0-9]].*//'`
  LTREL="-release $MAJOR"
  LTVER="-version-info `expr $MAJOR + $MINOR`:$MICRO:$MINOR"
AC_MSG_RESULT([/$MAJOR/$MAJOR:$MINOR:$MICRO (-$MAJOR.so.$MAJOR.$MINOR.$MICRO)])
AC_SUBST(LTREL)
AC_SUBST(LTVER)
AS_VAR_POPDEF([LTVER])dnl
AS_VAR_POPDEF([LTREL])dnl
AS_VAR_POPDEF([PATCH])dnl
AS_VAR_POPDEF([MICRO])dnl
AS_VAR_POPDEF([MINOR])dnl
AS_VAR_POPDEF([MAJOR])dnl
])
