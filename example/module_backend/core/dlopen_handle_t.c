#include "dlopen_handle_t.h"
#include <dlfcn.h>
#include <errno.h>
#include "../../backends.h" /// @todo FIXME this kind of include is dangerous

int create_dlopen_handle(struct dlopen_handle_t *dlopen_handle, const char *path, const char *symbol_name)
{
	int err;
	int dlclose_error;
	dlopen_handle->handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (!dlopen_handle->handle) {
		dnet_backend_log(DNET_LOG_ERROR, "module_backend: fail to dlopen %s : %s\n", path, dlerror());
		err = -ENOMEM;
		goto err_out_exit;
	}
	dlopen_handle->symbol = dlsym(dlopen_handle->handle, symbol_name);
	if (!dlopen_handle->symbol) {
		dnet_backend_log(DNET_LOG_ERROR, "module_backend: fail to dlsym %s : %s\n", symbol_name, dlerror());
		err = -EINVAL;
		goto err_out_dlsym;
	}
	return 0;
err_out_dlsym:
		dlclose_error=dlclose(dlopen_handle->handle);
		if (dlclose_error) {
			dnet_backend_log(DNET_LOG_ERROR, "module_backend: fail to dlclose %s : %s\n", symbol_name, dlerror());
			err=dlclose_error;
		}
err_out_exit:
		return err;
}

void destroy_dlopen_handle(struct dlopen_handle_t* dlopen_handle)
{
	dlclose(dlopen_handle->handle);
}
