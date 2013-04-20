#pragma once
#include <stddef.h>
#include "elliptics/packet.h"

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

struct module_backend_api_t;

typedef void (destroy_handler_t)(struct module_backend_api_t*);
typedef int (command_handler_t)(void *, void *, struct dnet_cmd *, void *);
typedef int (meta_write_handler_t)(void *, struct dnet_raw_id *, void *, size_t);

/**
 * You should provide this structure via @a module_constructor from module.
 * This is just a bunch of handlers that will be called on corresponding
 * event from elliptics. You can put you own data in private_data.
 */
struct module_backend_api_t {
	destroy_handler_t *destroy_handler; ///< destructor for this structure
	command_handler_t *command_handler;
	meta_write_handler_t *meta_write_handler;
	void *private_data; ///< your own data
};

void report_module_backend_error(const char *what);

struct module_backend_t;

#ifdef __cplusplus
}
#endif
