/*
* 2013+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
* 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

#ifndef SLRU_CACHE_HPP
#define SLRU_CACHE_HPP

#include "cache.hpp"
#include "react/react.hpp"

namespace ioremap { namespace cache {

using namespace react;

class slru_cache_t {
public:
	slru_cache_t(struct dnet_backend_io *backend, struct dnet_node *n, const std::vector<size_t> &cache_pages_max_sizes, unsigned sync_timeout);

	~slru_cache_t();

	int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data);

	std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io);

	int remove(const unsigned char *id, dnet_io_attr *io);

	int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd);

	void clear();

	cache_stats get_cache_stats() const;

private:
	struct dnet_backend_io *m_backend;
	struct dnet_node *m_node;
	std::mutex m_lock;
	size_t m_cache_pages_number;
	std::vector<size_t> m_cache_pages_max_sizes;
	std::vector<size_t> m_cache_pages_sizes;
	std::unique_ptr<lru_list_t[]> m_cache_pages_lru;
	std::thread m_lifecheck;
	treap_t m_treap;
	mutable cache_stats m_cache_stats;
	bool m_clear_occured;
	unsigned m_sync_timeout;

	slru_cache_t(const slru_cache_t &) = delete;

	bool need_exit() const
	{
		return dnet_need_exit(m_node) || m_backend->need_exit;
	}

	size_t get_next_page_number(size_t page_number) const {
		if (page_number == 0) {
			return 0;
		}
		return page_number - 1;
	}

	size_t get_previous_page_number(size_t page_number) const {
		return page_number + 1;
	}

	void sync_if_required(data_t* it, elliptics_unique_lock<std::mutex> &guard);

	void insert_data_into_page(const unsigned char *id, size_t page_number, data_t *data);

	void remove_data_from_page(const unsigned char *id, size_t page_number, data_t *data);

	void move_data_between_pages(const unsigned char *id,
								 size_t source_page_number,
								 size_t destination_page_number,
								 data_t *data);

	data_t* create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk);

	data_t* populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err);

	bool have_enough_space(const unsigned char *id, size_t page_number, size_t reserve);

	void resize_page(const unsigned char *id, size_t page_number, size_t reserve);

	void erase_element(data_t *obj);

	void sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp);

	void sync_element(data_t *obj);

	void sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj);

	void life_check(void);
};

}}


#endif // SLRU_CACHE_HPP
