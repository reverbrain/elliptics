#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Config data structure for module backend
 */
struct module_backend_config_t {
	char *module_path; ///< path to shared library
	char *symbol_name; ///< name of module_constructor in shared library
	char *module_argument; ///< argument to module_constructor
};

void destroy_module_backend_config(struct module_backend_config_t *module_backend_config);

struct dnet_config_entry * dnet_config_entries_module();
size_t dnet_config_entries_module_size();

#ifdef __cplusplus
}
#endif
