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
