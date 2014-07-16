#ifndef IOREMAP_ELLIPTICS_BACKEND_H
#define IOREMAP_ELLIPTICS_BACKEND_H

#include <elliptics/backends.h>

#ifdef __cplusplus

#include <string>
#include <vector>
#include <memory>

#if __GNUC__ == 4 && __GNUC_MINOR__ < 5
#  include <cstdatomic>
#else
#  include <atomic>
#endif

struct dnet_backend_config_entry
{
	dnet_config_entry *entry;
	std::vector<char> value_template;
	std::vector<char> value;
};

enum dnet_backend_state {
	dnet_backend_disabled,
	dnet_backend_enabled,
	dnet_backend_activating,
	dnet_backend_deactivating,
};

struct dnet_backend_info
{
	dnet_backend_info() : log(NULL), group(0), cache(NULL), state(new std::atomic_uint(dnet_backend_disabled))
	{
	}

	dnet_config_backend config_template;
	dnet_log *log;
	std::vector<dnet_backend_config_entry> options;
	int group;
	void *cache;
	std::string history;
	std::unique_ptr<std::atomic_uint> state;

	dnet_config_backend config;
	std::vector<char> data;
};

struct dnet_backend_info_list
{
	std::vector<dnet_backend_info> backends;
};

extern "C" {
#else // __cplusplus
typedef struct dnet_backend_info_list_t dnet_backend_info_list;
#endif // __cplusplus

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
