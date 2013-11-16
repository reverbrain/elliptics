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

#ifdef __cplusplus
extern "C" {
#endif


/**
 * This is a simple wrapper of libdl calls.
 */
struct dlopen_handle_t {
	void *handle;
	void *symbol;
};

int create_dlopen_handle(struct dlopen_handle_t *handle, const char *path, const char *symbol_name);
void destroy_dlopen_handle(struct dlopen_handle_t *handle);

#ifdef __cplusplus
}
#endif
