#pragma once
#include <elliptics/module_backend.h>
#include "dlopen_handle_t.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This is type of function we expect to find in dlopen'ed module.
 */
typedef struct module_backend_api_t * (module_constructor)(struct module_backend_config_t *);

/**
 * Main strunctire of module backend - it joins config,
 * handle of dynamically loaded library, and api of module.
 */
struct module_backend_t
{
	struct module_backend_config_t config;
	struct dlopen_handle_t dlopen_handle;
	struct module_backend_api_t *api;
};

#ifdef __cplusplus
}
#endif
