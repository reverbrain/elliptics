#pragma once
#include "module_backend_config_t.h"
#include "dlopen_handle_t.h"
#include "module_backend_api_t.h"

struct module_backend_t
{
	struct module_backend_config_t config;
	struct dlopen_handle_t dlopen_handle;
	struct module_backend_api_t* api;
};
