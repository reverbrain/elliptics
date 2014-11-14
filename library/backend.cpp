#include "elliptics.h"
#include "../monitor/monitor.hpp"
#include "../example/config.hpp"
#include "../bindings/cpp/functional_p.h"

#include <fstream>
#include <memory>

#include <fcntl.h>

static int dnet_ids_generate(struct dnet_node *n, const char *file, unsigned long long storage_free)
{
	const unsigned long long size_per_id = 100 * 1024 * 1024 * 1024ULL;
	const size_t num = storage_free / size_per_id + 1;
	dnet_raw_id tmp;
	const char *random_source = "/dev/urandom";
	int err = 0;

	std::ifstream in(random_source, std::ofstream::binary);
	std::ofstream out;

	if (!in) {
		err = -errno;
		dnet_log_err(n, "failed to open '%s' as source of ids file '%s'", random_source, file);
		goto err_out_exit;
	}

	out.open(file, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		dnet_log_err(n, "failed to open/create ids file '%s'", file);
		goto err_out_unlink;
	}

	for (size_t i = 0; i < num; ++i) {
		if (!in.read(reinterpret_cast<char *>(tmp.id), sizeof(tmp.id))) {
			err = -errno;
			dnet_log_err(n, "failed to read id from '%s'", random_source);
			goto err_out_unlink;
		}

		if (!out.write(reinterpret_cast<char *>(tmp.id), sizeof(tmp.id))) {
			err = -errno;
			dnet_log_err(n, "failed to write id into ids file '%s'", file);
			goto err_out_unlink;
		}
	}

	return 0;

err_out_unlink:
	out.close();
	unlink(file);
err_out_exit:
	return err;
}

static struct dnet_raw_id *dnet_ids_init(struct dnet_node *n, const char *hdir, int *id_num, unsigned long long storage_free, struct dnet_addr *cfg_addrs, size_t backend_id)
{
	int fd, err, num;
	const char *file = "ids";
	char path[strlen(hdir) + 1 + strlen(file) + 1]; /* / + null-byte */
	struct stat st;
	struct dnet_raw_id *ids;

	snprintf(path, sizeof(path), "%s/%s", hdir, file);

again:
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
				err = dnet_ids_update(n, 1, path, cfg_addrs, backend_id);
			if (err)
				err = dnet_ids_generate(n, path, storage_free);

			if (err)
				goto err_out_exit;

			goto again;
		}

		dnet_log_err(n, "failed to open ids file '%s'", path);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err)
		goto err_out_close;

	if (st.st_size % sizeof(struct dnet_raw_id)) {
		dnet_log(n, DNET_LOG_ERROR, "Ids file size (%lu) is wrong, must be modulo of raw ID size (%zu).",
				(unsigned long)st.st_size, sizeof(struct dnet_raw_id));
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_raw_id);
	if (!num) {
		dnet_log(n, DNET_LOG_ERROR, "No ids read, exiting.");
		err = -EINVAL;
		goto err_out_close;
	}

	if (n->flags & DNET_CFG_KEEPS_IDS_IN_CLUSTER)
		dnet_ids_update(n, 0, path, cfg_addrs, backend_id);

	ids = reinterpret_cast<struct dnet_raw_id *>(malloc(st.st_size));
	if (!ids) {
		err = -ENOMEM;
		goto err_out_close;
	}

	err = read(fd, ids, st.st_size);
	if (err != st.st_size) {
		err = -errno;
		dnet_log_err(n, "Failed to read ids file '%s'", path);
		goto err_out_free;
	}

	close(fd);

	*id_num = num;
	return ids;

err_out_free:
	free(ids);
err_out_close:
	close(fd);
err_out_exit:
	return NULL;
}

static int dnet_backend_io_init(struct dnet_node *n, struct dnet_backend_io *io, int io_thread_num, int nonblocking_io_thread_num)
{
	int err;

	err = dnet_backend_command_stats_init(io);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "dnet_backend_io_init: backend: %zu, failed to allocate command stat structure: %d",
				io->backend_id, err);
		goto err_out_exit;
	}

	err = dnet_work_pool_alloc(&io->pool.recv_pool, n, io, io_thread_num, DNET_WORK_IO_MODE_BLOCKING, dnet_io_process);
	if (err) {
		goto err_out_command_stats_cleanup;
	}
	err = dnet_work_pool_alloc(&io->pool.recv_pool_nb, n, io, nonblocking_io_thread_num, DNET_WORK_IO_MODE_NONBLOCKING, dnet_io_process);
	if (err) {
		err = -ENOMEM;
		goto err_out_free_recv_pool;
	}

	return 0;

err_out_free_recv_pool:
	n->need_exit = 1;
	dnet_work_pool_cleanup(&io->pool.recv_pool);
err_out_command_stats_cleanup:
	dnet_backend_command_stats_cleanup(io);
err_out_exit:
	return err;
}

static void dnet_backend_io_cleanup(struct dnet_node *n, struct dnet_backend_io *io)
{
	(void) n;

	dnet_work_pool_cleanup(&io->pool.recv_pool);
	dnet_work_pool_cleanup(&io->pool.recv_pool_nb);
	dnet_backend_command_stats_cleanup(io);

	dnet_log(n, DNET_LOG_NOTICE, "dnet_backend_io_cleanup: backend: %zu", io->backend_id);
}

static const char *elapsed(const dnet_time &start)
{
	static __thread char buffer[64];
	dnet_time end;
	dnet_current_time(&end);

	const unsigned long long nano = 1000 * 1000 * 1000;

	const unsigned long long delta = (end.tsec - start.tsec) * nano + end.tnsec - start.tnsec;

	snprintf(buffer, sizeof(buffer), "%lld.%06lld secs", delta / nano, (delta % nano) / 1000);
	return buffer;
}

int dnet_backend_init(struct dnet_node *node, size_t backend_id, int *state)
{
	int ids_num;
	struct dnet_raw_id *ids;

	auto &backends = node->config_data->backends->backends;
	if (backends.size() <= backend_id) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, invalid backend id", backend_id);
		return -EINVAL;
	}

	dnet_backend_info &backend = backends[backend_id];
	dnet_time start;
	dnet_current_time(&start);

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		*state = backend.state;
		if (backend.state != DNET_BACKEND_DISABLED) {
			dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, trying to activate not disabled backend, elapsed: %s",
				backend_id, elapsed(start));
			switch (*state) {
				case DNET_BACKEND_ENABLED:
					return -EALREADY;
				case DNET_BACKEND_ACTIVATING:
					return -EINPROGRESS;
				case DNET_BACKEND_DEACTIVATING:
					return -EAGAIN;
				case DNET_BACKEND_UNITIALIZED:
				default:
					return -EINVAL;
			}
		}
		backend.state = DNET_BACKEND_ACTIVATING;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_init: backend: %zu, initializing", backend_id);

	int err;
	dnet_backend_io *backend_io;

	try {
		using namespace ioremap::elliptics::config;
		auto &data = *static_cast<config_data *>(node->config_data);
		auto parser = data.parse_config();
		config cfg = parser->root();
		const config backends_config = cfg.at("backends");
		bool found = false;

		for (size_t index = 0; index < backends_config.size(); ++index) {
			const config backend_config = backends_config.at(index);
			const uint32_t config_backend_id = backend_config.at<uint32_t>("backend_id");
			if (backend_id == config_backend_id) {
				backend.parse(&data, backend_config);
				found = true;
				break;
			}
		}

		if (!found) {
			err = -EBADF;
			dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, have not found backend section in configuration file, elapsed: %s",
				backend_id, elapsed(start));
			goto err_out_exit;
		}
	} catch (std::bad_alloc &) {
		err = -ENOMEM;
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed as not enouh memory, elapsed: %s",
			backend_id, elapsed(start));
		goto err_out_exit;
	} catch (std::exception &exc) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to read configuration file: %s, elapsed: %s",
			backend_id, exc.what(), elapsed(start));
		err = -EBADF;
		goto err_out_exit;
	}

	backend.config = backend.config_template;
	backend.data.assign(backend.data.size(), '\0');
	backend.config.data = backend.data.data();
	backend.config.log = backend.log.get();

	backend_io = &node->io->backends[backend_id];
	backend_io->need_exit = 0;

	for (auto it = backend.options.begin(); it != backend.options.end(); ++it) {
		const dnet_backend_config_entry &entry = *it;
		/*
		 * Copy value data into temporal buffer, since callback can modify it.
		 */
		std::vector<char> tmp(entry.value_template.begin(), entry.value_template.end());
		entry.entry->callback(&backend.config, entry.entry->key, tmp.data());
	}

	err = backend.config.init(&backend.config);
	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init backend: %d, elapsed: %s",
			backend_id, err, elapsed(start));
		goto err_out_exit;
	}

	backend_io->cb = &backend.config.cb;

	err = dnet_backend_io_init(node, backend_io, backend.io_thread_num, backend.nonblocking_io_thread_num);
	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init io pool, err: %d, elapsed: %s",
			backend_id, err, elapsed(start));
		goto err_out_backend_cleanup;
	}

	if (backend.cache_config) {
		backend_io->cache = backend.cache = dnet_cache_init(node, backend_io, backend.cache_config.get());
		if (!backend.cache) {
			err = -ENOMEM;
			dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init cache, err: %d, elapsed: %s",
				backend_id, err, elapsed(start));
			goto err_out_backend_io_cleanup;
		}
	}

	ids_num = 0;
	ids = dnet_ids_init(node, backend.history.c_str(), &ids_num, backend.config.storage_free, node->addrs, backend_id);
	err = dnet_route_list_enable_backend(node->route, backend_id, backend.group, ids, ids_num);
	free(ids);

	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to add backend to route list, "
				"err: %d, elapsed: %s", backend_id, err, elapsed(start));
		goto err_out_cache_cleanup;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_init: backend: %zu, initialized, elapsed: %s", backend_id, elapsed(start));

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		dnet_current_time(&backend.last_start);
		backend.last_start_err = 0;
		backend.state = DNET_BACKEND_ENABLED;
	}
	return 0;

	dnet_route_list_disable_backend(node->route, backend_id);
err_out_cache_cleanup:
	if (backend.cache) {
		dnet_cache_cleanup(backend.cache);
		backend.cache = NULL;
		backend_io->cache = NULL;
	}
err_out_backend_io_cleanup:
	backend_io->need_exit = 1;
	dnet_backend_io_cleanup(node, backend_io);
	node->io->backends[backend_id].cb = NULL;
err_out_backend_cleanup:
	backend.config.cleanup(&backend.config);
err_out_exit:
	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		dnet_current_time(&backend.last_start);
		backend.last_start_err = err;
		backend.state = DNET_BACKEND_DISABLED;
	}
	return err;
}

int dnet_backend_cleanup(struct dnet_node *node, size_t backend_id, int *state)
{
	if (backend_id >= node->config_data->backends->backends.size()) {
		return -EINVAL;
	}

	dnet_backend_info &backend = node->config_data->backends->backends[backend_id];

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		*state = backend.state;
		if (backend.state != DNET_BACKEND_ENABLED) {
			dnet_log(node, DNET_LOG_ERROR, "backend_cleanup: backend: %zu, trying to destroy not activated backend",
				backend_id);
			switch (*state) {
				case DNET_BACKEND_DISABLED:
					return -EALREADY;
				case DNET_BACKEND_DEACTIVATING:
					return -EINPROGRESS;
				case DNET_BACKEND_ACTIVATING:
					return -EAGAIN;
				case DNET_BACKEND_UNITIALIZED:
				default:
					return -EINVAL;
			}
		}
		backend.state = DNET_BACKEND_DEACTIVATING;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_cleanup: backend: %zu, destroying", backend_id);

	if (node->route)
		dnet_route_list_disable_backend(node->route, backend_id);

	dnet_backend_io *backend_io = node->io ? &node->io->backends[backend_id] : NULL;

	// set @need_exit to true to force cache lifecheck thread to exit and slru cacge to sync all elements to backend
	// this also leads to IO threads to stop, but since we already removed itself from route table,
	// and cache syncs data to backend either in lifecheck thread or in destructor context,
	// it is safe to set @need_exit early
	if (backend_io)
		backend_io->need_exit = 1;

	dnet_log(node, DNET_LOG_INFO, "backend_cleanup: backend: %zu: cleaning cache", backend_id);
	dnet_cache_cleanup(backend.cache);
	backend.cache = NULL;

	dnet_log(node, DNET_LOG_INFO, "backend_cleanup: backend: %zu: cleaning io: %p", backend_id, backend_io);
	if (backend_io) {
		dnet_backend_io_cleanup(node, backend_io);
		backend_io->cb = NULL;
	}

	backend.config.cleanup(&backend.config);
	memset(&backend.config.cb, 0, sizeof(backend.config.cb));

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		backend.state = DNET_BACKEND_DISABLED;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_cleanup: backend: %zu, destroyed", backend_id);

	return 0;
}

int dnet_backend_init_all(struct dnet_node *node)
{
	int err = 1;
	bool all_ok = true;
	int state = DNET_BACKEND_ENABLED;

	auto &backends = node->config_data->backends->backends;

	if (node->config_data->parallel_start) {
		try {
			using ioremap::elliptics::session;
			using ioremap::elliptics::async_backend_control_result;

			session sess(node);
			sess.set_exceptions_policy(session::no_exceptions);
			sess.set_timeout(std::numeric_limits<unsigned>::max() / 2);

			session clean_sess = sess.clean_clone();

			std::vector<async_backend_control_result> results;

			for (size_t backend_id = 0; backend_id < backends.size(); ++backend_id) {
				dnet_backend_info &backend = node->config_data->backends->backends[backend_id];
				if (!backend.enable_at_start)
					continue;

				results.emplace_back(clean_sess.enable_backend(node->st->addr, backend_id));
			}

			async_backend_control_result result = ioremap::elliptics::aggregated(sess, results.begin(), results.end());
			result.wait();

			err = result.error().code();
		} catch (std::bad_alloc &) {
			return -ENOMEM;
		}
	} else {
		for (size_t backend_id = 0; backend_id < backends.size(); ++backend_id) {
			dnet_backend_info &backend = node->config_data->backends->backends[backend_id];
			if (!backend.enable_at_start)
				continue;

			int tmp = dnet_backend_init(node, backend_id, &state);
			if (!tmp) {
				err = 0;
			} else if (err == 1) {
				err = tmp;
				all_ok = false;
			}
		}
	}

	if (all_ok) {
		err = 0;
	} else if (err == 1) {
		err = -EINVAL;
	}

	dnet_log(node, err ? DNET_LOG_ERROR : DNET_LOG_NOTICE, "backend_init_all: finished initializing all backends: %d", err);

	return err;
}

void dnet_backend_cleanup_all(struct dnet_node *node)
{
	int state = DNET_BACKEND_ENABLED;

	auto &backends = node->config_data->backends->backends;
	for (size_t backend_id = 0; backend_id < backends.size(); ++backend_id) {
		if (backends[backend_id].state != DNET_BACKEND_DISABLED)
			dnet_backend_cleanup(node, backend_id, &state);
	}
}

static int dnet_backend_set_ids(dnet_node *node, uint32_t backend_id, dnet_raw_id *ids, uint32_t ids_count)
{
	auto &backends = node->config_data->backends->backends;
	if (backend_id >= backends.size()) {
		return -EINVAL;
	}

	dnet_backend_info &backend = backends[backend_id];

	if (backend.history.empty()) {
		dnet_log(node, DNET_LOG_ERROR, "backend_set_ids: backend_id: %u, failed to open temporary ids file: history is not specified", backend_id);
		return -EINVAL;
	}

	char tmp_ids[1024];
	char target_ids[1024];
	snprintf(tmp_ids, sizeof(tmp_ids), "%s/ids_%08x%08x", backend.history.c_str(), rand(), rand());
	snprintf(target_ids, sizeof(target_ids), "%s/ids", backend.history.c_str());
	int err = 0;

	std::ofstream out(tmp_ids, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		dnet_log(node, DNET_LOG_ERROR, "backend_set_ids: backend_id: %u, failed to open temporary ids file: %s, err: %d", backend_id, tmp_ids, err);
		return err;
	}

	try {
		out.write(reinterpret_cast<char *>(ids), ids_count * sizeof(dnet_raw_id));
		out.flush();
		out.close();

		if (!out) {
			err = -errno;
			dnet_log(node, DNET_LOG_ERROR, "backend_set_ids: backend_id: %u, failed to write ids to temporary file: %s, err: %d", backend_id, tmp_ids, err);
		} else {

			if (!err) {
				std::lock_guard<std::mutex> guard(*backend.state_mutex);
				switch (backend.state) {
					case DNET_BACKEND_ENABLED:
						err = std::rename(tmp_ids, target_ids);
						if (err)
							break;
						err = dnet_route_list_enable_backend(node->route, backend_id, backend.group, ids, ids_count);
						break;
					case DNET_BACKEND_DISABLED:
						err = std::rename(tmp_ids, target_ids);
						break;
					default:
						err = -EBUSY;
						break;
				}
			}
		}
	} catch (...) {
		out.close();
		err = -ENOMEM;
	}

	unlink(tmp_ids);
	return err;
}

void backend_fill_status_nolock(struct dnet_node *node, struct dnet_backend_status *status, size_t backend_id)
{
	if (!status)
		return;

	const auto &backends = node->config_data->backends->backends;
	const dnet_backend_info &backend = backends[backend_id];
	const dnet_backend_io &io = node->io->backends[backend_id];

	const auto &cb = backend.config.cb;

	status->backend_id = backend_id;
	status->state = backend.state;
	if (backend.state == DNET_BACKEND_ENABLED && cb.defrag_status)
		status->defrag_state = cb.defrag_status(cb.command_private);
	status->last_start = backend.last_start;
	status->last_start_err = backend.last_start_err;
	status->read_only = io.read_only;
	status->delay = io.delay;
}

void backend_fill_status(dnet_node *node, dnet_backend_status *status, size_t backend_id)
{
	const auto &backends = node->config_data->backends->backends;
	const dnet_backend_info &backend = backends[backend_id];
	std::lock_guard<std::mutex> guard(*backend.state_mutex);

	backend_fill_status_nolock(node, status, backend_id);
}

static int dnet_cmd_backend_control_dangerous(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	dnet_node *node = st->n;
	const auto &backends = node->config_data->backends->backends;

	struct dnet_backend_control *control = reinterpret_cast<dnet_backend_control *>(data);

	if (control->backend_id >= backends.size()) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: there is no such backend: %u, state: %s", control->backend_id, dnet_state_dump_addr(st));
		return -EINVAL;
	}

	if (cmd->size != sizeof(dnet_backend_control) + control->ids_count * sizeof(dnet_raw_id)) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: command size is not enough for ids, state: %s", dnet_state_dump_addr(st));
		return -EINVAL;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_control: received BACKEND_CONTROL: backend_id: %u, command: %u, state: %s",
		control->backend_id, control->command, dnet_state_dump_addr(st));

	const dnet_backend_info &backend = backends[control->backend_id];
	if (backend.state == DNET_BACKEND_UNITIALIZED) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: there is no such backend: %u, state: %s", control->backend_id, dnet_state_dump_addr(st));
		return -EINVAL;
	}

	dnet_backend_io &io = node->io->backends[control->backend_id];

	int state = DNET_BACKEND_DISABLED;
	const dnet_backend_callbacks &cb = backend.config.cb;

	int err = -ENOTSUP;
	switch (dnet_backend_command(control->command)) {
	case DNET_BACKEND_ENABLE:
		err = dnet_backend_init(node, control->backend_id, &state);
		break;
	case DNET_BACKEND_DISABLE:
		err = dnet_backend_cleanup(node, control->backend_id, &state);
		break;
	case DNET_BACKEND_START_DEFRAG:
		if (cb.defrag_start) {
			err = cb.defrag_start(cb.command_private);
		} else {
			err = -ENOTSUP;
		}
		break;
	case DNET_BACKEND_SET_IDS:
		err = dnet_backend_set_ids(st->n, control->backend_id, control->ids, control->ids_count);
		break;
	case DNET_BACKEND_READ_ONLY:
		if (io.read_only) {
			err = -EALREADY;
		} else {
			io.read_only = 1;
			err = 0;
		}
		break;
	case DNET_BACKEND_WRITEABLE:
		if (!io.read_only) {
			err = -EALREADY;
		} else {
			io.read_only = 0;
			err = 0;
		}
		break;
	case DNET_BACKEND_CTL:
		io.delay = control->delay;
		err = 0;
		break;
	}

	char buffer[sizeof(dnet_backend_status_list) + sizeof(dnet_backend_status)];
	memset(buffer, 0, sizeof(buffer));

	dnet_backend_status_list *list = reinterpret_cast<dnet_backend_status_list *>(buffer);
	dnet_backend_status *status = reinterpret_cast<dnet_backend_status *>(list + 1);

	list->backends_count = 1;
	backend_fill_status(node, status, control->backend_id);

	if (err) {
		dnet_send_reply(st, cmd, list, sizeof(buffer), true);
	} else {
		cmd->flags &= ~DNET_FLAGS_NEED_ACK;
		err = dnet_send_reply(st, cmd, list, sizeof(buffer), false);
		if (err) {
			cmd->flags |= DNET_FLAGS_NEED_ACK;
			return 0;
		}
	}

	return err;
}

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	dnet_node *node = st->n;

	if (cmd->size < sizeof(dnet_backend_control)) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: command size is not enough for dnet_backend_control, state: %s", dnet_state_dump_addr(st));
		return -EINVAL;
	}

	struct dnet_backend_control *control = reinterpret_cast<dnet_backend_control *>(data);

	try {
		blackhole::log::attributes_t attributes = {
			blackhole::attribute::make("backend_id", uint32_t(control->backend_id))
		};

		blackhole::scoped_attributes_t scoped(*node->log, std::move(attributes));

		return dnet_cmd_backend_control_dangerous(st, cmd, data);
	} catch (std::bad_alloc &) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: insufficient memory");
		return -ENOMEM;
	} catch (std::exception &exc) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: %s", exc.what());
		return -EINVAL;
	}
}

int dnet_cmd_backend_status(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	(void) data;
	dnet_node *node = st->n;

	const auto &backends = node->config_data->backends->backends;
	const size_t total_size = sizeof(dnet_backend_status_list) + backends.size() * sizeof(dnet_backend_status);

	std::unique_ptr<dnet_backend_status_list, free_destroyer> list(reinterpret_cast<dnet_backend_status_list *>(malloc(total_size)));
	if (!list) {
		return -ENOMEM;
	}
	memset(list.get(), 0, total_size);

	list->backends_count = backends.size();

	size_t j = 0;

	for (size_t i = 0; i < backends.size(); ++i) {
		dnet_backend_status &status = list->backends[j];
		backend_fill_status(st->n, &status, i);
		if (status.state != DNET_BACKEND_UNITIALIZED)
			++j;
	}

	list->backends_count = j;

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;

	int err = dnet_send_reply(st, cmd, list.get(), total_size, false);

	if (err != 0) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
	}

	return err;
}

void dnet_backend_info::parse(ioremap::elliptics::config::config_data *data, const ioremap::elliptics::config::config &backend)
{
	std::string type = backend.at<std::string>("type");

	dnet_config_backend *backends_info[] = {
		dnet_eblob_backend_info(),
		dnet_file_backend_info(),
#ifdef HAVE_MODULE_BACKEND_SUPPORT
		dnet_module_backend_info(),
#endif
	};

	bool found_backend = false;

	for (size_t i = 0; i < sizeof(backends_info) / sizeof(backends_info[0]); ++i) {
		dnet_config_backend *current_backend = backends_info[i];
		if (type == current_backend->name) {
			config_template = *current_backend;
			config = *current_backend;
			this->data.resize(config.size, '\0');
			found_backend = true;
			break;
		}
	}

	if (!found_backend)
		throw ioremap::elliptics::config::config_error() << backend.at("type").path() << " is unknown backend";

	group = backend.at<uint32_t>("group");
	history = backend.at<std::string>("history");
	cache = NULL;

	if (backend.has("cache")) {
		const auto cache = backend.at("cache");
		cache_config = ioremap::cache::cache_config::parse(cache);
	} else if (data->cache_config) {
		cache_config = blackhole::utils::make_unique<ioremap::cache::cache_config>(*data->cache_config);
	}

	io_thread_num = backend.at("io_thread_num", data->cfg_state.io_thread_num);
	nonblocking_io_thread_num = backend.at("nonblocking_io_thread_num", data->cfg_state.nonblocking_io_thread_num);

	for (int i = 0; i < config.num; ++i) {
		dnet_config_entry &entry = config.ent[i];
		if (backend.has(entry.key)) {
			std::string key_str = entry.key;
			std::vector<char> key(key_str.begin(), key_str.end());
			key.push_back('\0');

			std::string value_str = backend.at(entry.key).to_string();
			std::vector<char> value(value_str.begin(), value_str.end());
			value.push_back('\0');

			dnet_backend_config_entry option = {
				&entry,
				value
			};

			options.emplace_back(std::move(option));
		}
	}
}
