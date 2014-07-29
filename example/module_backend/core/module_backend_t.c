/*
 * Copyright 2008+ Ivan Tolstosheyev <itroot@yandex-team.ru>
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

#include "elliptics/backends.h"
#include "elliptics/module_backend.h"
#include "module_backend_t.h"

static void module_backend_cleanup(void *private_data)
{
	struct module_backend_t *module_backend = private_data;
	module_backend->api->destroy_handler(module_backend->api);
	destroy_dlopen_handle(&module_backend->dlopen_handle);
	destroy_module_backend_config(&module_backend->config);
}

static int dnet_module_config_init(struct dnet_config_backend *b)
{
	int err;
	module_constructor* constructor;
	struct module_backend_t *module_backend = b->data;

	module_backend->config.log = b->log;

	err = create_dlopen_handle(b->log, &module_backend->dlopen_handle, module_backend->config.module_path, module_backend->config.symbol_name);
	if (err) {
		dnet_backend_log(b->log, DNET_LOG_ERROR, "module_backend: fail to create dlopen handle from %s", module_backend->config.module_path);
		err = -ENOMEM;
		goto err_out_exit;
	}

	constructor = module_backend->dlopen_handle.symbol;
	module_backend->api = constructor(&module_backend->config);
	if (!module_backend->api) {
		dnet_backend_log(b->log, DNET_LOG_ERROR, "module_backend: fail to create api from %s", module_backend->config.module_path);
		err = -ENOMEM;
		goto err_out_constructor;
	}

	b->cb.command_private = module_backend;
	b->cb.command_handler = module_backend->api->command_handler;
	b->cb.iterator        = module_backend->api->iterator;
	b->cb.backend_cleanup = module_backend_cleanup;
	dnet_backend_log(b->log, DNET_LOG_NOTICE, "module_backend: load successful");
	return 0;

err_out_constructor:
		destroy_dlopen_handle(&module_backend->dlopen_handle);

err_out_exit:
		return err;
}

static void dnet_module_config_cleanup(struct dnet_config_backend *b)
{
	struct module_backend_t *module_backend = b->data;
	module_backend_cleanup(module_backend);
}

int read_config_string(char *value, char **result)
{
	int err;
	char *value_copy = strdup(value);
	if (!value_copy) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	*result = value_copy;
	return 0;

err_out_exit:
		return err;
}

int read_config_entry(struct dnet_config_backend *b, char *key, char *value)
{
	struct module_backend_t *module_backend = b->data;
	struct module_backend_config_t *backend_config = &module_backend->config;

	if (!strcmp(key, "module_path")) {
		return read_config_string(value, &backend_config->module_path);
	} else if (!strcmp(key, "symbol_name")) {
		return read_config_string(value, &backend_config->symbol_name);
	} else if (!strcmp(key, "module_argument")) {
		return read_config_string(value, &backend_config->module_argument);
	} else {
		return -EINVAL;
	}
	return -EINVAL;
}

struct dnet_config_entry dnet_cfg_entries_module[] = {
	{"module_path", read_config_entry},
	{"symbol_name", read_config_entry},
	{"module_argument", read_config_entry},
};

static struct dnet_config_backend dnet_module_backend = {
	.name			= "module",
	.size			= sizeof(struct module_backend_t),
	.init			= dnet_module_config_init,
	.cleanup		= dnet_module_config_cleanup,
	.ent			= dnet_cfg_entries_module,
	.num			= ARRAY_SIZE(dnet_cfg_entries_module),
};

struct dnet_config_backend *dnet_module_backend_info(void)
{
	return &dnet_module_backend;
}

void destroy_module_backend_config(struct module_backend_config_t *module_backend_config)
{
	free(module_backend_config->module_path);
	free(module_backend_config->symbol_name);
	free(module_backend_config->module_argument);
}

void report_module_backend_error(dnet_logger *log, const char *what)
{
	dnet_backend_log(log, DNET_LOG_ERROR, "module_backend: failed: %s", what);
}
