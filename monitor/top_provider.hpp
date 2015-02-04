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

struct key_stat_event {
	struct dnet_id	id;
	uint64_t		size;
	double			frequency;
	time_t			last_access;

	typedef const decltype(id) *key_type;
	typedef size_t time_type;

	key_type get_key() const { return &id; }

	uint64_t get_weight() const { return size; }
	void set_weight(uint64_t weight) { size = weight; }

	double get_frequency() const { return frequency; }
	void set_frequency(double freq) { frequency = freq; }

	time_type get_time() const {return last_access; }
	void set_time(time_type time) { last_access = time; }

	inline static int key_compare(const key_type &lhs, const key_type &rhs) {
		return dnet_id_cmp(lhs, rhs);
	}

	inline static bool weight_compare(const key_stat_event &lhs, const key_stat_event &rhs) {
		return lhs.get_weight() < rhs.get_weight();
	}

	inline static int time_compare(const time_type &lhs, const time_type &rhs) {
		if (lhs < rhs) {
			return 1;
		}

		if (lhs > rhs) {
			return -1;
		}

		return 0;
	}
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
