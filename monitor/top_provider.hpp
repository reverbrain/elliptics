/*
 * Copyright 2015+ Budnik Andrey <budnik27@gmail.com>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_MONITOR_TOP_PROVIDER_HPP
#define __DNET_MONITOR_TOP_PROVIDER_HPP

#include "statistics.hpp"
#include "event_stats.hpp"

namespace ioremap { namespace monitor {

class key_stat_event;

}}  /* namespace ioremap::monitor */

namespace ioremap { namespace cache {

template<>
struct treap_node_traits<ioremap::monitor::key_stat_event>
{
	typedef const struct dnet_id* key_type;
	typedef size_t priority_type;
};

}}  /* namespace ioremap::cache */

namespace ioremap { namespace monitor {

class key_stat_event : public ioremap::cache::treap_node_t<key_stat_event> {
public:
	key_stat_event() = default;
	key_stat_event(struct dnet_id &id, uint64_t size, double frequency, time_t last_access)
	: m_id(id), m_size(size), m_frequency(frequency), m_last_access(last_access)
	{}

	uint64_t get_weight() const { return m_size; }
	void set_weight(uint64_t weight) { m_size = weight; }

	double get_frequency() const { return m_frequency; }
	void set_frequency(double freq) { m_frequency = freq; }

	time_t get_time() const {return m_last_access; }
	void set_time(time_t time) { m_last_access = time; }

	// treap_node_t
	typedef ioremap::cache::treap_node_traits<key_stat_event>::key_type key_type;
	typedef ioremap::cache::treap_node_traits<key_stat_event>::priority_type priority_type;

	key_type get_key() const { return &m_id; }
	priority_type get_priority() const { return m_last_access; }

	inline static int key_compare(const key_type &lhs, const key_type &rhs) {
		return dnet_id_cmp(lhs, rhs);
	}

	inline static int priority_compare(const priority_type &lhs, const priority_type &rhs) {
		if (lhs < rhs) {
			return 1;
		}

		if (lhs > rhs) {
			return -1;
		}

		return 0;
	}

private:
	struct dnet_id	m_id;
	uint64_t		m_size;
	double			m_frequency;
	time_t			m_last_access;
};

/*!
 * Provider statistics of top keys arranged by approximate traffic size and frequency
 */
class top_provider : public stat_provider {
public:
	top_provider(struct dnet_node *node, size_t top_k, size_t events_size, int period_in_seconds);

	virtual std::string json(uint64_t categories) const;

	void update_stats(struct dnet_cmd *cmd, uint64_t size);

private:
	struct dnet_node *m_node;
	mutable event_stats<key_stat_event, mutex_lock_policy> m_stats;
	size_t m_top_k;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_TOP_PROVIDER_HPP */
