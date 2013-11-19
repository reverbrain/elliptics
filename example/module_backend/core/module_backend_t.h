/*
 * Copyright 2013+ Ivan Tolstosheyev <itroot@yandex-team.ru>
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
