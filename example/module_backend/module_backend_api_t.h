#pragma once

#include "../backends.h"

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
	destroy_handler_t* destroy_handler;
	command_handler_t* command_handler;
	meta_write_handler_t* meta_write_handler;
	void* private_data;
};
