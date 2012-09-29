execute_process(COMMAND python -c "from distutils import sysconfig; print sysconfig.get_python_lib(),"
	RESULT_VARIABLE ret_var
	OUTPUT_VARIABLE PYTHON_EXTENSION_DIR
	OUTPUT_STRIP_TRAILING_WHITESPACE)
