/*
 * Copyright 2013+ Ivan Tolstosheyev <itroot@yandex-team.ru>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dlopen_handle_t.h"
#include <dlfcn.h>
#include <errno.h>
#include "elliptics/backends.h"

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
		}

err_out_exit:
		return err;
}

void destroy_dlopen_handle(struct dlopen_handle_t* dlopen_handle)
{
	dlclose(dlopen_handle->handle);
}
