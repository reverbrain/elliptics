#include <memory>
#include <fcntl.h>
#include "elliptics.h"
#include "../monitor/monitor.hpp"
#include <fstream>

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

int dnet_backend_init(struct dnet_node *node, size_t backend_id, unsigned *state)
{
	int ids_num;
	struct dnet_raw_id *ids;

	auto &backends = node->config_data->backends->backends;
	if (backends.size() <= backend_id) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, invalid backend id", backend_id);
		return -EINVAL;
	}

	dnet_backend_info &backend = backends[backend_id];

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		*state = backend.state;
		if (backend.state != DNET_BACKEND_DISABLED) {
			dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, trying to activate not disabled backend", backend_id);
			if (*state == DNET_BACKEND_ENABLED)
				return -EALREADY;
			else if (*state == DNET_BACKEND_ACTIVATING)
				return -EINPROGRESS;
			else /*if (*state == DNET_BACKEND_DEACTIVATING)*/
				return -EAGAIN;
			return -EINVAL;
		}
		backend.state = DNET_BACKEND_ACTIVATING;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_init: backend: %zu, initializing", backend_id);

	backend.config = backend.config_template;
	backend.data.assign(backend.data.size(), '\0');
	backend.config.data = backend.data.data();
	backend.config.log = backend.log;

	dnet_backend_io *backend_io = &node->io->backends[backend_id];
	backend_io->need_exit = 0;

	for (auto it = backend.options.begin(); it != backend.options.end(); ++it) {
		dnet_backend_config_entry &entry = *it;
		entry.value.assign(entry.value_template.begin(), entry.value_template.end());
		entry.entry->callback(&backend.config, entry.entry->key, entry.value.data());
	}

	int err = backend.config.init(&backend.config);
	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init backend: %d", backend_id, err);
		goto err_out_exit;
	}

	if (node->cache_size) {
		backend_io->cache = backend.cache = dnet_cache_init(node, backend_io);
		if (!backend.cache) {
			dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init cache, err: %d", backend_id, err);
			goto err_out_backend_cleanup;
		}
	}

	backend_io->cb = &backend.config.cb;

	err = dnet_backend_io_init(node, backend_io);
	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to init io pool, err: %d", backend_id, err);
		goto err_out_cache_cleanup;
	}

	ids_num = 0;
	ids = dnet_ids_init(node, backend.history.c_str(), &ids_num, backend.config.storage_free, node->addrs, backend_id);
	err = dnet_route_list_enable_backend(node->route, backend_id, backend.group, ids, ids_num);
	free(ids);

	if (err) {
		dnet_log(node, DNET_LOG_ERROR, "backend_init: backend: %zu, failed to add backend to route list, err: %d", backend_id, err);
		goto err_out_backend_io_cleanup;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_init: backend: %zu, initialized", backend_id);

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		dnet_current_time(&backend.last_start);
		backend.last_start_err = 0;
		backend.state = DNET_BACKEND_ENABLED;
	}
	return 0;

	dnet_route_list_disable_backend(node->route, backend_id);
err_out_backend_io_cleanup:
	backend_io->need_exit = 1;
	dnet_backend_io_cleanup(node, backend_io);
	node->io->backends[backend_id].cb = NULL;
err_out_cache_cleanup:
	if (backend.cache) {
		dnet_cache_cleanup(backend.cache);
		backend.cache = NULL;
		backend_io->cache = NULL;
	}
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

int dnet_backend_cleanup(struct dnet_node *node, size_t backend_id, unsigned *state)
{
	if (backend_id >= node->config_data->backends->backends.size()) {
		return -EINVAL;
	}

	dnet_backend_info &backend = node->config_data->backends->backends[backend_id];

	{
		std::lock_guard<std::mutex> guard(*backend.state_mutex);
		*state = backend.state;
		if (backend.state != DNET_BACKEND_ENABLED) {
			dnet_log(node, DNET_LOG_ERROR, "backend_cleanup: backend: %zu, trying to destroy not activated backend", backend_id);
			if (*state == DNET_BACKEND_DISABLED)
				return -EALREADY;
			else if (*state == DNET_BACKEND_DEACTIVATING)
				return -EINPROGRESS;
			else /*if (*state == DNET_BACKEND_ACTIVATING)*/
				return -EAGAIN;
		}
		backend.state = DNET_BACKEND_DEACTIVATING;
	}

	dnet_log(node, DNET_LOG_INFO, "backend_cleanup: backend: %zu, destroying", backend_id);

	dnet_backend_io *backend_io = node->io ? &node->io->backends[backend_id] : NULL;
	if (backend_io)
		backend_io->need_exit = 1;

	if (node->route)
		dnet_route_list_disable_backend(node->route, backend_id);

	if (backend_io)
		dnet_backend_io_cleanup(node, backend_io);

	dnet_cache_cleanup(backend.cache);
	if (backend_io)
		backend_io->cb = NULL;
	backend.cache = NULL;
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
	unsigned state = DNET_BACKEND_ENABLED;

	auto &backends = node->config_data->backends->backends;
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

	if (all_ok) {
		dnet_monitor_init_backends_stat_provider(node);
		return 0;
	}
	else if (err == 1)
		return -EINVAL;
	else
		return err;
}

void dnet_backend_cleanup_all(struct dnet_node *node)
{
	unsigned state = DNET_BACKEND_ENABLED;

	auto &backends = node->config_data->backends->backends;
	for (size_t backend_id = 0; backend_id < backends.size(); ++backend_id) {
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
	char tmp_ids[1024];
	char target_ids[1024];
	snprintf(tmp_ids, sizeof(tmp_ids), "%s/ids_%08x%08x", backend.history.c_str(), rand(), rand());
	snprintf(target_ids, sizeof(target_ids), "%s/ids", backend.history.c_str());
	int err = 0;

	std::ofstream out(tmp_ids, std::ofstream::binary | std::ofstream::trunc);
	if (!out) {
		err = -errno;
		dnet_log(node, DNET_LOG_ERROR, "backend_set_ids: failed to open temporary ids file: %s, err: %d", tmp_ids, err);
		return err;
	}

	try {
		out.write(reinterpret_cast<char *>(ids), ids_count * sizeof(dnet_raw_id));
		out.flush();
		out.close();

		if (!out) {
			err = -errno;
			dnet_log(node, DNET_LOG_ERROR, "backend_set_ids: failed to write ids to temporary file: %s, err: %d", tmp_ids, err);
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

void backend_fill_status_nolock(struct dnet_node *node, struct dnet_backend_status *status, size_t backend_id) {
	if (!status)
		return;

	const auto &backends = node->config_data->backends->backends;
	const dnet_backend_info &backend = backends[backend_id];

	const auto &cb = backend.config.cb;

	status->backend_id = backend_id;
	status->state = backend.state;
	if (backend.state == DNET_BACKEND_ENABLED && cb.defrag_status)
		status->defrag_state = cb.defrag_status(cb.command_private);
	status->last_start = backend.last_start;
	status->last_start_err = backend.last_start_err;
}

void backend_fill_status(dnet_node *node, dnet_backend_status *status, size_t backend_id)
{
	const auto &backends = node->config_data->backends->backends;
	const dnet_backend_info &backend = backends[backend_id];
	std::lock_guard<std::mutex> guard(*backend.state_mutex);

	backend_fill_status_nolock(node, status, backend_id);
}

int dnet_cmd_backend_control(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	dnet_node *node = st->n;
	const auto &backends = node->config_data->backends->backends;

	if (cmd->size < sizeof(dnet_backend_control)) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: command size is not enough for dnet_backend_control, state: %s", dnet_state_dump_addr(st));
		return -EINVAL;
	}

	struct dnet_backend_control *control = reinterpret_cast<dnet_backend_control *>(data);

	if (control->backend_id >= backends.size()) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: there is no such backend: %u, state: %s", control->backend_id, dnet_state_dump_addr(st));
		return -EINVAL;
	}

	if (cmd->size != sizeof(dnet_backend_control) + control->ids_count * sizeof(dnet_raw_id)) {
		dnet_log(node, DNET_LOG_ERROR, "backend_control: command size is not enough for ids, state: %s", dnet_state_dump_addr(st));
		return -EINVAL;
	}

	const dnet_backend_info &backend = backends[control->backend_id];

	unsigned state = DNET_BACKEND_DISABLED;
	const dnet_backend_callbacks &cb = backend.config.cb;

	int err = 0;
	switch (dnet_backend_command(control->command)) {
	case DNET_BACKEND_ENABLE:
		err = dnet_backend_init(st->n, control->backend_id, &state);
		break;
	case DNET_BACKEND_DISABLE:
		err = dnet_backend_cleanup(st->n, control->backend_id, &state);
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

	for (size_t i = 0; i < backends.size(); ++i) {
		dnet_backend_status &status = list->backends[i];
		backend_fill_status(st->n, &status, i);
	}

	cmd->flags &= ~DNET_FLAGS_NEED_ACK;

	int err = dnet_send_reply(st, cmd, list.get(), total_size, false);

	if (err != 0) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
	}

	return err;
}
