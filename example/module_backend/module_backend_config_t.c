#include "module_backend_config_t.h"
#include "module_backend_t.h"

void destroy_module_backend_config(struct module_backend_config_t* module_backend_config)
{
	free(module_backend_config->module_path);
	free(module_backend_config->symbol_name);
	free(module_backend_config->module_argument);
}

int read_config_string(char *value, char** result)
{
	int err;
	char* value_copy=strdup(value);
	if (NULL==value_copy) {
		err=-ENOMEM;
		goto err_strdup;
	}
	*result=value_copy;
	return 0;
	err_strdup:
		return err;
}

int read_config_entry(struct dnet_config_backend *b, char *key, char *value)
{
	struct module_backend_t* module_backend=b->data;
	struct module_backend_config_t* backend_config=&module_backend->config;
	if (0==strcmp(key, "module_path")) {
		return read_config_string(value, &backend_config->module_path);
	} else if (0==strcmp(key, "symbol_name")) {
		return read_config_string(value, &backend_config->symbol_name);
	} else if (0==strcmp(key, "module_argument")) {
		return read_config_string(value, &backend_config->module_argument);
	} else {
		return -EINVAL;
	}
}

struct dnet_config_entry dnet_cfg_entries_module[] = {
	{"module_path", read_config_entry},
	{"symbol_name", read_config_entry},
	{"module_argument", read_config_entry},
};

struct dnet_config_entry* dnet_config_entries_module()
{
	return dnet_cfg_entries_module;
}

size_t dnet_config_entries_module_size()
{
	return ARRAY_SIZE(dnet_cfg_entries_module);
}
