#ifndef IOREMAP_ELLIPTICS_BACKEND_H
#define IOREMAP_ELLIPTICS_BACKEND_H

#include <elliptics/backends.h>

#ifdef __cplusplus

#include <string>
#include <vector>
#include <memory>
#include <mutex>

#include <elliptics/error.hpp>

namespace ioremap { namespace elliptics { namespace config {
class config;
class config_data;
}}}

namespace ioremap { namespace cache {

struct cache_config
{
	size_t			size;
	size_t			count;
	unsigned		sync_timeout;
	std::vector<size_t>	pages_proportions;

	static std::unique_ptr<cache_config> parse(const ioremap::elliptics::config::config &cache);
};

}}

/**
 * This structure holds config value read from config file
 * @entry.key contains config key, @value_template holds value for given key
 *
 * When backend is being initialized, it calls @entry.callback() function for each config entry
 *
 * Please note that backend initalization copies value into temporal copy,
 * since @entry.callback() can modify this data.
 */
struct dnet_backend_config_entry
{
	dnet_config_entry *entry;
	std::vector<char> value_template;
};

struct dnet_backend_info
{
	static blackhole::log::attributes_t make_attributes(uint32_t backend_id)
	{
		blackhole::log::attributes_t result = {
			blackhole::attribute::make("backend_id", backend_id)
		};
		return std::move(result);
	}

	dnet_backend_info(dnet_logger &logger, uint32_t backend_id) :
		log(new dnet_logger(logger, make_attributes(backend_id))),
		group(0), cache(NULL), enable_at_start(false),
		state_mutex(new std::mutex), state(DNET_BACKEND_UNITIALIZED),
		io_thread_num(0), nonblocking_io_thread_num(0)
	{
		dnet_empty_time(&last_start);
		last_start_err = 0;
		memset(&config_template, 0, sizeof(config_template));
		memset(&config, 0, sizeof(config));
	}

	dnet_backend_info(const dnet_backend_info &other) = delete;
	dnet_backend_info &operator =(const dnet_backend_info &other) = delete;

	dnet_backend_info(dnet_backend_info &&other) ELLIPTICS_NOEXCEPT :
		config_template(other.config_template),
		log(std::move(other.log)),
		options(std::move(other.options)),
		group(other.group),
		cache(other.cache),
		history(other.history),
		enable_at_start(other.enable_at_start),
		state_mutex(std::move(other.state_mutex)),
		state(other.state),
		last_start(other.last_start),
		last_start_err(other.last_start_err),
		config(other.config),
		data(std::move(other.data)),
		cache_config(std::move(other.cache_config)),
		io_thread_num(other.io_thread_num),
		nonblocking_io_thread_num(other.nonblocking_io_thread_num)
	{
	}

	dnet_backend_info &operator =(dnet_backend_info &&other) ELLIPTICS_NOEXCEPT
	{
		config_template = other.config_template;
		log = std::move(other.log);
		options = std::move(other.options);
		group = other.group;
		cache = other.cache;
		history = other.history;
		enable_at_start = other.enable_at_start;
		state_mutex = std::move(other.state_mutex);
		state = other.state;
		last_start = other.last_start;
		last_start_err = other.last_start_err;
		config = other.config;
		data = std::move(other.data);
		cache_config = std::move(other.cache_config);
		io_thread_num = other.io_thread_num;
		nonblocking_io_thread_num = other.nonblocking_io_thread_num;

		return *this;
	}

	void parse(ioremap::elliptics::config::config_data *data, const ioremap::elliptics::config::config &config);

	dnet_config_backend config_template;
	std::unique_ptr<dnet_logger> log;
	std::vector<dnet_backend_config_entry> options;
	uint32_t group;
	void *cache;
	std::string history;
	bool enable_at_start;

	std::unique_ptr<std::mutex> state_mutex;
	dnet_backend_state state;
	dnet_time last_start;
	int last_start_err;

	dnet_config_backend config;
	std::vector<char> data;

	std::unique_ptr<ioremap::cache::cache_config> cache_config;
	int io_thread_num;
	int nonblocking_io_thread_num;
};

struct dnet_backend_info_list
{
	std::vector<dnet_backend_info> backends;
};

extern "C" {
#else // __cplusplus
typedef struct dnet_backend_info_list_t dnet_backend_info_list;
#endif // __cplusplus

int dnet_backend_init(struct dnet_node *n, size_t backend_id, int *state);
int dnet_backend_cleanup(struct dnet_node *n, size_t backend_id, int *state);

int dnet_backend_init_all(struct dnet_node *n);
void dnet_backend_cleanup_all(struct dnet_node *n);

size_t dnet_backend_info_list_count(dnet_backend_info_list *backends);

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

/*
 * Fills \a status of backend with \a backend_id without any locks
 */
void backend_fill_status_nolock(struct dnet_node *node, struct dnet_backend_status *status, size_t backend_id);

/*
 * Locks backend with \a backend_id state mutex and fills \a status
 */
void backend_fill_status(struct dnet_node *node, struct dnet_backend_status *status, size_t backend_id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // IOREMAP_ELLIPTICS_BACKEND_H
