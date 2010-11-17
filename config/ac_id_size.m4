AC_DEFUN([AC_ID_SIZE], [
	AC_MSG_CHECKING(the ID size)
	AC_ARG_WITH([id-size],
		AC_HELP_STRING([--with-id-size=@<:@ARG@:>@],
			[Build with the different ID size (ARG=bytes)]),
		[am_id_size=$withval], [am_id_size=64])
	AC_MSG_RESULT([$am_id_size] bytes)

	AC_DEFINE_UNQUOTED(CONFIG_ID_SIZE, $am_id_size, [Defined for the configured ID size])
])

