#ifndef IOREMAP_ELLIPTICS_BACKEND_H
#define IOREMAP_ELLIPTICS_BACKEND_H

#include <elliptics/backends.h>

#ifdef __cplusplus

#include <string>
#include <vector>

struct dnet_backend_config_entry
{
	dnet_config_entry *entry;
	std::vector<char> value_template;
	std::vector<char> value;
};

struct dnet_backend_info
{
	dnet_config_backend config_template;
	dnet_log *log;
	std::vector<dnet_backend_config_entry> options;
	int group;
	void *cache;
	std::string history;

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
