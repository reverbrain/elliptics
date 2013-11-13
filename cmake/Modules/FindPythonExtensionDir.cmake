execute_process(COMMAND "${PYTHON_EXECUTABLE}" -c "from distutils import sysconfig; print sysconfig.get_python_lib(prefix='${CMAKE_INSTALL_PREFIX}'),"
	RESULT_VARIABLE ret_var
	OUTPUT_VARIABLE PYTHON_EXTENSION_DIR
	OUTPUT_STRIP_TRAILING_WHITESPACE)
