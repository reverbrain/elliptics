#include "dlopen_handle_t.h"
#include <dlfcn.h>
#include <errno.h>
#include "../backends.h" /// @todo FIXME this kind of include is dangerous

int create_dlopen_handle(struct dlopen_handle_t* dlopen_handle, const char* path, const char* symbol_name)
{
	int err;
	dlopen_handle->handle=dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (NULL==dlopen_handle->handle) {
		dnet_backend_log(DNET_LOG_ERROR, "Fail to dlopen %s : %s\n", path, dlerror());
		err=-ENOMEM;
		goto err;
	}
	dlopen_handle->symbol=dlsym(dlopen_handle->handle, symbol_name);
	if (NULL==dlopen_handle->symbol) {
		dnet_backend_log(DNET_LOG_ERROR, "Fail to dlsym %s : %s\n", symbol_name, dlerror());
		err=-EINVAL;
		goto err_dlsym;
	}
	return 0;
	err_dlsym:
		;
		int result=dlclose(dlopen_handle->handle);
		if (result!=0) {
			err=result;
		}
	err:
		return err;
}

void destroy_dlopen_handle(struct dlopen_handle_t* dlopen_handle)
{
	dlclose(dlopen_handle->handle);
}
