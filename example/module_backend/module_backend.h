#pragma once

#include "module_backend_config_t.h"
#include "module_backend_api_t.h"

typedef struct module_backend_api_t* (module_constructor)(struct module_backend_config_t*);

