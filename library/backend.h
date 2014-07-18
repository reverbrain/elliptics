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

struct dnet_backend_info
{
	dnet_backend_info() : log(NULL), group(0), cache(NULL), enable_at_start(true), state(new std::atomic_uint(DNET_BACKEND_DISABLED))
	{
	}

	dnet_config_backend config_template;
	dnet_log *log;
	std::vector<dnet_backend_config_entry> options;
	int group;
	void *cache;
	std::string history;
	bool enable_at_start;
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

int dnet_backend_init(struct dnet_node *n, size_t backend_id, unsigned *state);
int dnet_backend_cleanup(struct dnet_node *n, size_t backend_id, unsigned *state);

int dnet_backend_init_all(struct dnet_node *n);
void dnet_backend_cleanup_all(struct dnet_node *n);

size_t dnet_backend_info_list_count(dnet_backend_info_list *backends);

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
