#pragma once
#include <stddef.h>
#include "../backends.h"

struct module_backend_config_t {
	char *module_path;
	char *symbol_name;
	char *module_argument;
};

void destroy_module_backend_config(struct module_backend_config_t* module_backend_config);

struct dnet_config_entry* dnet_config_entries_module();
size_t dnet_config_entries_module_size();
