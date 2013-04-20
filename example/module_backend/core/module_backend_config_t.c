#include <elliptics/module_backend.h>
#include "module_backend_t.h"
#include "../../backends.h"

void destroy_module_backend_config(struct module_backend_config_t *module_backend_config)
{
	free(module_backend_config->module_path);
	free(module_backend_config->symbol_name);
	free(module_backend_config->module_argument);
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

struct dnet_config_entry * dnet_config_entries_module()
{
	return dnet_cfg_entries_module;
}

size_t dnet_config_entries_module_size()
{
	return ARRAY_SIZE(dnet_cfg_entries_module);
}
