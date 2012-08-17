install-exec-hook:
	if test x${DESTDIR} != x; then ${PYTHON} setup.py install --root=${DESTDIR}; else ${PYTHON} setup.py install --prefix=${prefix}; fi

EXTRA_DIST = __init__.py setup.py
