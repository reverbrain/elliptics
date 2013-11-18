#ifndef LRU_CACHE_HPP
#define LRU_CACHE_HPP

#include "cache.hpp"

namespace ioremap { namespace cache {

class lru_cache_t {
public:
	lru_cache_t(struct dnet_node *n, size_t max_size);

	~lru_cache_t();

	void stop();

	int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data);

	std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io);

	int remove(const unsigned char *id, dnet_io_attr *io);

	int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd);

private:
	bool m_need_exit;
	struct dnet_node *m_node;
	size_t m_cache_size, m_max_cache_size;
	std::mutex m_lock;
	iset_t m_set;
	lru_list_t m_lru;
	life_set_t m_lifeset;
	sync_set_t m_syncset;
	std::thread m_lifecheck;

	lru_cache_t(const lru_cache_t &) = delete;

	iset_t::iterator create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk);

	iset_t::iterator populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err);

	void resize(size_t reserve);

	void erase_element(data_t *obj);

	void sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp);

	void sync_element(data_t *obj);

	void sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj);

	void life_check(void);
};

}}

#endif // LRU_CACHE_HPP
