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

#ifndef __DNET_MONITOR_EVENT_STATS_HPP
#define __DNET_MONITOR_EVENT_STATS_HPP

#include "cache/treap.hpp"

#include <mutex>
#include <algorithm>
#include <functional> // not2
#include <vector>
#include <stack>

namespace ioremap { namespace monitor {

template<typename E>
class event_stats
{
	// events stored in fixed-size LRU that is implemented using treap
	typedef ioremap::cache::treap<E> treap_t;
public:
	/*!
	 * \internal
	 *
	 * Constructor parameters: \a events_size - maximum memory available for internal data structures,
	 * \a period_in_seconds - observable period of time
	 */
	event_stats(size_t events_size, int period_in_seconds)
	: m_num_events(0),
	 m_max_events(bytes_to_num_events(events_size)),
	 m_period(period_in_seconds)
	{}

	~event_stats() {
		clear();
	}

	/*!
	 * \internal
	 *
	 * Add \a event with \a time occurence of this event to update statistics.
	 * Complexity: O(log N) on average, where N - number of containing events
	 */
	void add_event(const E &event, time_t time)
	{
		std::unique_lock<std::mutex> locker(m_lock);
		auto it = m_treap.find(event.get_key());
		if (it) {
			update_weight(*it, time, m_period, event.get_weight());
			update_frequency(*it, time, m_period, 1.);
			it->set_time(time);
			m_treap.decrease_key(it);
		} else {
			if (m_num_events < m_max_events) {
				m_treap.insert(new E(event));
				++m_num_events;
			} else {
				auto t = m_treap.top();
				m_treap.erase(t);
				*t = event;
				m_treap.insert(t);
			}
		}
	}

	/*!
	 * \internal
	 *
	 * Get top \a k events with highest weight, \a time - current time,
	 * \a top_size - result container, that should support push_back operation and random access iterators.
	 * Complexity: O(N * log N) worst case complexity,
	 *             O(N * log k) average case complexity, where N - number of containing events
	 */
	template< typename ResultContainer >
	void get_top(size_t k, time_t time, ResultContainer &top_size)
	{
		std::vector<typename treap_t::p_node_type> top_nodes;

		{
			std::unique_lock<std::mutex> locker(m_lock);
			treap_to_container(m_treap.top(), top_nodes);

			for (auto it = top_nodes.begin(); it != top_nodes.end(); ++it) {
				auto n = *it;
				if (check_expiration(n, time, m_period)) {
					m_treap.erase(n);
					delete n;
					--m_num_events;
				} else {
					top_size.push_back(*n);
				}
			}
		}

		k = std::min(top_size.size(), k);
		std::function<decltype(weight_compare)> comparator_weight(weight_compare);
		std::partial_sort(top_size.begin(), top_size.begin() + k, top_size.end(), std::not2(comparator_weight));
		top_size.resize(k);
	}

private:
	template<typename Container>
	void treap_to_container(typename treap_t::p_node_type node, Container &result) const {
		std::stack<typename treap_t::p_node_type> path;

		while(node || !path.empty()) { // inorder bst traversal
			if (node) {
				path.push(node);
				node = node->l;
			} else {
				node = path.top();
				path.pop();
				result.push_back(node);
				node = node->r;
			}
		}
	}

	void clear() {
		while (!m_treap.empty()) {
			auto t = m_treap.top();
			m_treap.erase(t);
			delete t;
		}
	}

	inline static size_t bytes_to_num_events(size_t bytes) {
		return bytes / sizeof(E);
	}

	/*!
	 * \internal
	 *
	 * Update \a event weight, taking into account frequency expiration (params \a time and \a window_size used)
	 * and event \a size
	 */
	inline static void update_weight(E &event, time_t time, size_t window_size, size_t size) {
		double delta = compute_expiration(time, event.get_time(), window_size);
		event.set_weight(delta * event.get_weight() + size);
	}

	/*!
	 * \internal
	 *
	 * Update \a event frequency, taking into account frequency expiration (params \a time and \a window_size used)
	 * and event \a freq - frequency
	 */
	inline static void update_frequency(E &event, time_t time, size_t window_size, double freq) {
		double delta = compute_expiration(time, event.get_time(), window_size);
		event.set_frequency(delta * event.get_frequency() + freq);
	}

	/*!
	 * \internal
	 *
	 * Check whether \a event last \a time occurance outside time window of \a window_size seconds
	 */
	inline static bool check_expiration(const E *event, time_t time, size_t window_size) {
		return static_cast<size_t>(time - event->get_time()) > window_size;
	}

	/*
	 * Basic idea of moving sum:
	 * Let there be N events: e[1], e[2], ..., e[N];
	 * each event e[i] has some integrable value w[i], time of event occurance t[i];
	 * also there is a time window, every t[i] must be within this time window [current_time - window_size, current_time].
	 * Approximate sum of w[i], i=1..N computed in following way:
	 * sum(i) = sum(i-1) * (1.0 - (t[i] - t[i-1]) / window_size) + w[i]
	 * sum(1) = w[1]
	 * sum_of_all_events = sum(N)
	 */
	inline static double compute_expiration(time_t current_time, time_t last_time, size_t window_size) {
		double delta = 1. - (current_time - last_time) / (double)window_size;
		if (delta < 0.) delta = 0.;
		return delta;
	}

	inline static bool weight_compare(const E &lhs, const E &rhs) {
		return lhs.get_weight() < rhs.get_weight();
	}

private:
	size_t m_num_events;
	const size_t m_max_events;
	const int m_period;
	treap_t m_treap;
	std::mutex m_lock;
};

}}  /* namespace ioremap::monitor */

#endif // __DNET_MONITOR_EVENT_STATS_HPP
