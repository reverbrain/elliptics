#!/usr/bin/make -f

DEB_PYTHON_SYSTEM=pycentral
DEB_PYTHON_MODULE_PACKAGES := elliptics-client
export DH_PYCENTRAL=nomove

binary-install/elliptics-client::
	cp -r $(cdbs_python_destdir)/usr/lib/python*/site-packages/* $(cdbs_python_destdir)/../elliptics-client/$(PYTHON_LIB_PATH)/; echo -n
	rm -rf $(cdbs_python_destdir)/usr/lib/python*/site-packages; echo -n
