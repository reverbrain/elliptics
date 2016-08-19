#include "route.h"
#include "elliptics.h"
#include <elliptics/utils.hpp>

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data __unused)
{
	struct dnet_node *n = st->n;
	int err = -ENXIO;
	int version[4] = {0, 0, 0, 0};
	int indexes_shard_count = 0;

	dnet_version_decode(&cmd->id, version);
	dnet_indexes_shard_count_decode(&cmd->id, &indexes_shard_count);
	memcpy(st->version, version, sizeof(st->version));

	/* check received version at first and if it is ok - send self version */
	err = dnet_version_check(st, version);
	if (err)
		goto err_out_exit;

	/* send self version only if client has right version */
	dnet_version_encode(&cmd->id);
	dnet_indexes_shard_count_encode(&cmd->id, n->indexes_shard_count);

	dnet_log(n, DNET_LOG_INFO, "%s: reverse lookup command: client indexes shard count: %d, server indexes shard count: %d",
			dnet_state_dump_addr(st),
			indexes_shard_count,
			n->indexes_shard_count);

	{
		pthread_mutex_lock(&n->state_lock);
		err = dnet_route_list_send_all_ids_nolock(st, &cmd->id, cmd->trans, DNET_CMD_REVERSE_LOOKUP, 1, 0);
		pthread_mutex_unlock(&n->state_lock);
	}

err_out_exit:
	if (err) {
		cmd->flags |= DNET_FLAGS_NEED_ACK;
		dnet_state_reset(st, err);
	}
	return err;
}

static int dnet_cmd_join_client(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_addr_container *cnt = (dnet_addr_container *)data;
	struct dnet_addr laddr;
	char client_addr[128], server_addr[128];
	int i, err, idx;
	bool state_already_reseted = false;
	uint32_t j;
	struct dnet_id_container *id_container;
	struct dnet_backend_ids **backends;
	struct dnet_backend_ids *backend;

	dnet_socket_local_addr(st->read_s, &laddr);
	idx = dnet_local_addr_index(n, &laddr);

	dnet_addr_string_raw(&st->addr, client_addr, sizeof(client_addr));
	dnet_addr_string_raw(&laddr, server_addr, sizeof(server_addr));

	if (cmd->size < sizeof(struct dnet_addr_container)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"cmd-size: %llu, must be more than addr_container: %zd",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				(unsigned long long)cmd->size, sizeof(struct dnet_addr_container));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_addr_container(cnt);

	if (cmd->size < sizeof(struct dnet_addr_container) +
			cnt->addr_num * sizeof(struct dnet_addr) +
			sizeof(struct dnet_id_container)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"cmd-size: %llu, must be more than addr_container+addrs: %zd, addr_num: %d",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				(unsigned long long)cmd->size,
				sizeof(struct dnet_addr_container) +
					cnt->addr_num * sizeof(struct dnet_addr) +
					sizeof(struct dnet_id_container),
				cnt->addr_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	if (idx < 0 || idx >= cnt->addr_num || cnt->addr_num != n->addr_num) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, "
				"address idx: %d, received addr-num: %d, local addr-num: %d",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				idx, cnt->addr_num, n->addr_num);
		err = -EINVAL;
		goto err_out_exit;
	}

	id_container = (struct dnet_id_container *)((char *)data + sizeof(struct dnet_addr_container) +
				cnt->addr_num * sizeof(struct dnet_addr));

	err = dnet_validate_id_container(id_container,
			cmd->size - sizeof(struct dnet_addr) * cnt->addr_num - sizeof(struct dnet_addr_container));
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: invalid join request: client: %s -> %s, failed to parse id_container, err: %d",
				dnet_dump_id(&cmd->id), client_addr, server_addr, err);
		goto err_out_exit;
	}

	backends = (struct dnet_backend_ids **)malloc(id_container->backends_count * sizeof(struct dnet_backends_id *));
	if (!backends) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dnet_id_container_fill_backends(id_container, backends);

	dnet_log(n, DNET_LOG_NOTICE, "%s: join request: client: %s -> %s, "
			"address idx: %d, received addr-num: %d, local addr-num: %d, backends-num: %d",
			dnet_dump_id(&cmd->id), client_addr, server_addr,
			idx, cnt->addr_num, n->addr_num, id_container->backends_count);

	for (i = 0; i < id_container->backends_count; ++i) {
		backend = backends[i];
		for (j = 0; j < backend->ids_count; ++j) {
			dnet_log(n, DNET_LOG_NOTICE, "%s: join request: client: %s -> %s, "
				"received backends: %d/%d, ids: %d/%d, addr-num: %d, idx: %d, "
				"backend_id: %d, group_id: %d, id: %s.",
				dnet_dump_id(&cmd->id), client_addr, server_addr,
				i, id_container->backends_count,
				j, backend->ids_count, cnt->addr_num, idx,
				backend->backend_id, backend->group_id,
				dnet_dump_id_str(backend->ids[j].id));
		}
	}

	err = dnet_state_move_to_dht(st, cnt->addrs, cnt->addr_num);
	if (err) {
		// dnet_state_move_to_dht internally resets the state, no need to reset it second time
		state_already_reseted = true;
		goto err_out_free;
	}

	for (i = 0; i < id_container->backends_count; ++i) {
		err = dnet_idc_update_backend(st, backends[i]);
		if (err) {
			pthread_mutex_lock(&n->state_lock);
			dnet_idc_destroy_nolock(st);
			pthread_mutex_unlock(&n->state_lock);

			goto err_out_move_back;
		}
	}

	dnet_state_set_server_prio(st);

	dnet_log(n, DNET_LOG_INFO, "%s: client's join request completed: client: %s -> %s, "
			"address idx: %d, received addr-num: %d, local addr-num: %d, backends-num: %d",
			dnet_dump_id(&cmd->id), client_addr, server_addr,
			idx, cnt->addr_num, n->addr_num, id_container->backends_count);


	goto err_out_free;

err_out_move_back:
	pthread_mutex_lock(&n->state_lock);
	list_move_tail(&st->node_entry, &n->empty_state_list);
	list_move_tail(&st->storage_state_entry, &n->storage_state_list);
	pthread_mutex_unlock(&n->state_lock);
err_out_free:
	free(backends);
err_out_exit:

	// JOIN is critical command, if it fails we have to reset the connection
	if (err && !state_already_reseted)
		dnet_state_reset(st, err);

	return err;
}

static int dnet_state_join_nolock(struct dnet_net_state *st)
{
	int err;
	struct dnet_node *n = st->n;
	struct dnet_addr laddr;
	char client_addr[128], server_addr[128];

	struct dnet_id id;
	memset(&id, 0, sizeof(id));

	err = dnet_route_list_send_all_ids_nolock(st, &id, 0, DNET_CMD_JOIN, 0, 1);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send join request to %s.",
			dnet_dump_id(&id), dnet_addr_string(&st->addr));
		// JOIN is critical command
		dnet_state_reset(st, err);
		goto err_out_exit;
	}

	dnet_addr_string_raw(&st->addr, server_addr, sizeof(client_addr));
	dnet_socket_local_addr(st->read_s, &laddr);
	dnet_addr_string_raw(&laddr, client_addr, sizeof(server_addr));

	st->__join_state = DNET_JOIN;

err_out_exit:
	dnet_log(n, err < 0 ? DNET_LOG_ERROR : DNET_LOG_INFO,
			"%s: %s joined network, server's join request completed: client (this node): %s -> %s, err: %d",
			dnet_dump_id(&id),
			err == 0 ? "successfully" : "unsuccessfully",
			client_addr, server_addr, err);
	return err;
}

dnet_route_list::dnet_route_list(dnet_node *node) : m_node(node)
{
}

dnet_route_list::~dnet_route_list()
{
}

struct dnet_backend_update_cmd
{
	dnet_cmd cmd;
	dnet_id_container container;
	dnet_backend_ids ids;
};

int dnet_route_list::enable_backend(size_t backend_id, int group_id, dnet_raw_id *ids, size_t ids_count)
{
	dnet_cmd *cmd = reinterpret_cast<dnet_cmd *>(malloc(sizeof(dnet_backend_update_cmd) + ids_count * sizeof(dnet_raw_id)));
	if (!cmd)
		return -ENOMEM;
	std::unique_ptr<dnet_cmd, free_destroyer> cmd_guard(cmd);

	dnet_id_container *container = reinterpret_cast<dnet_id_container *>(cmd + 1);

	memset(cmd, 0, sizeof(dnet_backend_update_cmd));

	dnet_backend_ids *backend_ids = reinterpret_cast<dnet_backend_ids *>(container + 1);

	cmd->cmd = DNET_CMD_UPDATE_IDS;
	cmd->flags = DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
	cmd->size = sizeof(dnet_backend_update_cmd) + ids_count * sizeof(dnet_raw_id) - sizeof(dnet_cmd);
	container->backends_count = 1;
	backend_ids->backend_id = backend_id;
	backend_ids->group_id = group_id;
	backend_ids->ids_count = ids_count;
	memcpy(backend_ids->ids, ids, ids_count * sizeof(dnet_raw_id));

	assert_perror(dnet_validate_id_container(container, cmd->size));

	std::lock_guard<std::mutex> lock_guard(m_mutex);

	m_backends.resize(std::max(m_backends.size(), backend_id + 1));

	backend_info &backend = m_backends[backend_id];
	backend.activated = true;
	backend.group_id = group_id;
	backend.ids.assign(ids, ids + ids_count);

	int err = dnet_idc_update_backend(m_node->st, backend_ids);
	send_update_to_states(cmd, backend_id);
	return err;
}

int dnet_route_list::disable_backend(size_t backend_id)
{
	std::lock_guard<std::mutex> lock_guard(m_mutex);

	if (backend_id >= m_backends.size()) {
		return 0;
	}

	backend_info &backend = m_backends[backend_id];
	backend.activated = false;

	{
		dnet_pthread_lock_guard guard(m_node->state_lock);
		dnet_idc_remove_backend_nolock(m_node->st, backend_id);
	}

	dnet_backend_update_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cmd.cmd.cmd = DNET_CMD_UPDATE_IDS;
	cmd.cmd.flags = DNET_FLAGS_DIRECT | DNET_FLAGS_NOLOCK;
	cmd.cmd.size = sizeof(dnet_backend_update_cmd) - sizeof(dnet_cmd);
	cmd.container.backends_count = 1;
	cmd.ids.backend_id = backend_id;
	cmd.ids.flags = DNET_BACKEND_DISABLE;

	assert_perror(dnet_validate_id_container(&cmd.container, cmd.cmd.size));

	send_update_to_states(&cmd.cmd, backend_id);

	return 0;
}

int dnet_route_list::on_reverse_lookup(dnet_net_state *st, dnet_cmd *cmd, void *data)
{
	std::lock_guard<std::mutex> lock_guard(m_mutex);
	return dnet_cmd_reverse_lookup(st, cmd, data);
}

int dnet_route_list::on_join(dnet_net_state *st, dnet_cmd *cmd, void *data)
{
	return dnet_cmd_join_client(st, cmd, data);
}

int dnet_route_list::join(dnet_net_state *st)
{
	std::lock_guard<std::mutex> lock_guard(m_mutex);
	dnet_pthread_lock_guard guard(st->n->state_lock);

	return dnet_state_join_nolock(st);
}

int dnet_route_list::send_all_ids_nolock(dnet_net_state *st, dnet_id *id,
		uint64_t trans, unsigned int command, int reply, int direct)
{
	using namespace ioremap::elliptics;

	struct dnet_addr laddr;
	char client_addr[128], server_addr[128];

	dnet_socket_local_addr(st->read_s, &laddr);

	dnet_addr_string_raw(&st->addr, server_addr, sizeof(server_addr));
	dnet_addr_string_raw(&laddr, client_addr, sizeof(client_addr));

	size_t total_size = sizeof(dnet_addr_cmd) + m_node->addr_num * sizeof(dnet_addr) + sizeof(dnet_id_container);
	size_t backends_count = 0;

	for (auto it = m_backends.begin(); it != m_backends.end(); ++it) {
		backend_info &backend = *it;
		if (!backend.activated)
			continue;

		++backends_count;
		total_size += sizeof(dnet_backend_ids);
		total_size += it->ids.size() * sizeof(dnet_raw_id);
	}

	// id can be NULL if this is a JOIN request command to remote server
	if (id->group_id == 0 && m_backends.size() != 0)
		id->group_id = m_backends[0].group_id;

	void *buffer = std::calloc(1, total_size);
	if (!buffer)
		return -ENOMEM;
	std::unique_ptr<void, free_destroyer> buffer_guard(buffer);

	dnet_cmd *cmd = reinterpret_cast<dnet_cmd *>(buffer);
	cmd->id = *id;
	cmd->trans = trans;
	cmd->cmd = command;
	cmd->flags = DNET_FLAGS_NOLOCK;
	if (direct)
		cmd->flags |= DNET_FLAGS_DIRECT;
	if (reply)
		cmd->flags |= DNET_FLAGS_REPLY;
	cmd->size = total_size - sizeof(dnet_cmd);

	dnet_addr_container *addr_container = reinterpret_cast<dnet_addr_container *>(cmd + 1);
	addr_container->addr_num = addr_container->node_addr_num = m_node->addr_num;

	dnet_addr *addrs = addr_container->addrs;
	memcpy(addrs, m_node->addrs, m_node->addr_num * sizeof(dnet_addr));

	dnet_id_container *id_container = reinterpret_cast<dnet_id_container *>(addrs + m_node->addr_num);
	id_container->backends_count = backends_count;

	char *ptr = reinterpret_cast<char *>(id_container + 1);

	for (size_t backend_id = 0; backend_id < m_backends.size(); ++backend_id) {
		backend_info &backend = m_backends[backend_id];
		if (!backend.activated)
			continue;

		dnet_backend_ids *backend_ids = reinterpret_cast<dnet_backend_ids *>(ptr);

		backend_ids->backend_id = backend_id;
		backend_ids->group_id = backend.group_id;
		backend_ids->ids_count = backend.ids.size();

		dnet_convert_dnet_backend_ids(backend_ids);

		dnet_raw_id *ids = backend_ids->ids;
		memcpy(ids, backend.ids.data(), backend.ids.size() * sizeof(dnet_raw_id));

		ptr += backend.ids.size() * sizeof(dnet_raw_id) + sizeof(dnet_backend_ids);
	}

	dnet_log(st->n, DNET_LOG_INFO, "%s: sending ids: command: %s [%d], trans: %lld, "
			"client (this node): %s -> %s, "
			"address idx: %d, container addr-num: %d, local addr-num: %d, backends-num: %d",
			dnet_dump_id(&cmd->id),
			dnet_cmd_string(command), command, (unsigned long long)trans,
			client_addr, server_addr,
			st->idx, addr_container->addr_num, st->n->addr_num, id_container->backends_count);

	dnet_convert_id_container(id_container);

	st->__ids_sent = 1;
	return dnet_send(st, buffer, total_size);
}

void dnet_route_list::send_update_to_states(dnet_cmd *cmd, size_t backend_id)
{
	dnet_net_state *state;
	dnet_pthread_lock_guard guard(m_node->state_lock);

	list_for_each_entry(state, &m_node->storage_state_list, storage_state_entry) {
		if (!state->__ids_sent || state == m_node->st)
			continue;

		int err = dnet_send(state, cmd, cmd->size + sizeof(dnet_cmd));
		if (err != 0) {
			dnet_log(m_node, DNET_LOG_ERROR,
					"failed to send route-list update for backend: %zu to state: %s, "
					"reseting the state, err: %d",
				backend_id, dnet_state_dump_addr(state), err);

			// We have not send route list update to this client, so we have to drop connection to it
			dnet_state_reset(state, err);
		} else {
			dnet_log(m_node, DNET_LOG_NOTICE,
				"succesffuly sent route-list update for backend: %zu to state: %s",
				backend_id, dnet_state_dump_addr(state));
		}
	}
}

dnet_route_list *dnet_route_list_create(dnet_node *node)
{
	try {
		return new dnet_route_list(node);
	} catch (...) {
		return NULL;
	}
}

void dnet_route_list_destroy(dnet_route_list *route)
{
	delete route;
}

int dnet_route_list_reverse_lookup(dnet_net_state *st, dnet_cmd *cmd, void *data)
{
	return safe_call(st->n->route, &dnet_route_list::on_reverse_lookup, st, cmd, data);
}

int dnet_route_list_join(dnet_net_state *st, dnet_cmd *cmd, void *data)
{
	return safe_call(st->n->route, &dnet_route_list::on_join, st, cmd, data);
}

int dnet_state_join(struct dnet_net_state *st)
{
	return safe_call(st->n->route, &dnet_route_list::join, st);
}

int dnet_route_list_enable_backend(dnet_route_list *route, size_t backend_id, int group_id, dnet_raw_id *ids, size_t ids_count)
{
	return safe_call(route, &dnet_route_list::enable_backend, backend_id, group_id, ids, ids_count);
}

int dnet_route_list_disable_backend(dnet_route_list *route, size_t backend_id)
{
	return safe_call(route, &dnet_route_list::disable_backend, backend_id);
}

int dnet_route_list_send_all_ids_nolock(dnet_net_state *st, dnet_id *id,
		uint64_t trans, unsigned int command, int reply, int direct)
{
	return safe_call(st->n->route, &dnet_route_list::send_all_ids_nolock, st, id, trans, command, reply, direct);
}
