#ifndef IOREMAP_ELLIPTICS_ROUTE_H
#define IOREMAP_ELLIPTICS_ROUTE_H

#include <elliptics/packet.h>
#include <elliptics/interface.h>

#ifdef __cplusplus
#include <vector>
#include <mutex>

class dnet_pthread_mutex
{
public:
	dnet_pthread_mutex(pthread_mutex_t &mutex) : m_mutex(mutex)
	{
	}

	void lock()
	{
		pthread_mutex_lock(&m_mutex);
	}

	void unlock()
	{
		pthread_mutex_unlock(&m_mutex);
	}
private:
	pthread_mutex_t &m_mutex;
};

class dnet_pthread_lock_guard
{
public:
	dnet_pthread_lock_guard(pthread_mutex_t &mutex) : m_mutex(mutex), m_lock_guard(m_mutex)
	{
	}

private:
	dnet_pthread_mutex m_mutex;
	std::lock_guard<dnet_pthread_mutex> m_lock_guard;
};

class dnet_route_list
{
public:
	dnet_route_list(dnet_node *node);
	~dnet_route_list();

	int enable_backend(size_t backend_id, int group_id, dnet_raw_id *ids, size_t ids_count);
	int disable_backend(size_t backend_id);

	int on_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
	int on_join(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

	int join(dnet_net_state *st);
	int send_all_ids_nolock(dnet_net_state *st, struct dnet_id *id, uint64_t trans,
		unsigned int command, int reply, int direct);
protected:
	void send_update_to_states(dnet_cmd *cmd, size_t backend_id);

private:
	dnet_node *m_node;

	struct backend_info {
		backend_info() : activated(false), group_id(0)
		{
		}

		bool activated;
		int group_id;
		std::vector<dnet_raw_id> ids;
	};

	std::mutex m_mutex;
	std::vector<backend_info> m_backends;
};

struct free_destroyer
{
	void operator() (void *buffer)
	{
		free(buffer);
	}
};

extern "C" {
#else // __cplusplus
typedef struct dnet_route_list_t dnet_route_list;
#endif // __cplusplus

dnet_route_list *dnet_route_list_create(struct dnet_node *node);
void dnet_route_list_destroy(dnet_route_list *route);

int dnet_route_list_enable_backend(dnet_route_list *route, size_t backend_id, int group_id, struct dnet_raw_id *ids, size_t ids_count);
int dnet_route_list_disable_backend(dnet_route_list *route, size_t backend_id);

int dnet_route_list_send_all_ids_nolock(struct dnet_net_state *st, struct dnet_id *id, uint64_t trans,
	unsigned int command, int reply, int direct);

int dnet_route_list_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);
int dnet_route_list_join(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IOREMAP_ELLIPTICS_ROUTE_H
