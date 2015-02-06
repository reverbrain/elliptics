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

#ifndef EVENT_STATS_HPP
#define EVENT_STATS_HPP

#include "cache/treap.hpp"

#include <mutex>
#include <algorithm>
#include <functional> // not2
#include <stack>

namespace ioremap { namespace monitor {

class mutex_lock_policy
{
	typedef std::mutex mutex_t;
public:
	class unique_lock {
	public:
		unique_lock(mutex_lock_policy *policy)
		: lock_(policy->get_lock())
		{}
	private:
		std::unique_lock<mutex_t> lock_;
	};

	mutex_t &get_lock() { return mut_; }
private:
	mutex_t mut_;
};

class null_lock_policy
{
public:
	class unique_lock {
	public:
		unique_lock(null_lock_policy *policy) { (void) policy; }
	};
};

template<typename E, typename lock_policy = null_lock_policy>
class event_stats : private lock_policy
{
	typedef ioremap::cache::treap<E> treap_t;
public:
	event_stats(size_t events_size, int period_in_seconds)
	: num_events(0),
	 max_events(bytes_to_num_events(events_size)),
	 period(period_in_seconds)
	{}

	~event_stats() {
		clear();
	}

	void add_event(const E &event, time_t time)
	{
		typename lock_policy::unique_lock lock(this);
		auto it = treap.find(event.get_key());
		if (it) {
			update_weight(*it, time, period, event.get_weight());
			update_frequency(*it, time, period, 1.);
			it->set_time(time);
			treap.decrease_key(it);
		} else {
			if (num_events < max_events) {
				treap.insert(new E(event));
				++num_events;
			} else {
				auto t = treap.top();
				treap.erase(t);
				*t = event;
				treap.insert(t);
			}
		}
	}

	template< typename ResultContainer >
	void get_top(size_t k, time_t time, ResultContainer &top_size)
	{
		std::vector< typename treap_t::p_node_type > top_nodes;

		{
			typename lock_policy::unique_lock lock(this);
			treap_to_container(treap.top(), top_nodes);

			for (auto it = top_nodes.begin(); it != top_nodes.end(); ++it) {
				auto n = *it;
				if (check_expiration(n, time, period)) {
					treap.erase(n);
					delete n;
					--num_events;
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
		while (!treap.empty()) {
			auto t = treap.top();
			treap.erase(t);
			delete t;
		}
	}

	inline static size_t bytes_to_num_events(size_t bytes) {
		return bytes / sizeof(E);
	}

	inline static void update_weight(E &event, time_t time, size_t window_size, size_t size) {
		double delta = compute_expiration(time, event.get_time(), window_size);
		event.set_weight(delta * event.get_weight() + size);
	}

	inline static void update_frequency(E &event, time_t time, size_t window_size, double freq) {
		double delta = compute_expiration(time, event.get_time(), window_size);
		event.set_frequency(delta * event.get_frequency() + freq);
	}

	inline static bool check_expiration(const E *event, time_t time, size_t window_size) {
		return static_cast<size_t>(time - event->get_time()) > window_size;
	}

	inline static double compute_expiration(time_t current_time, time_t last_time, size_t window_size) {
		double delta = 1. - (current_time - last_time) / (double)window_size;
		if (delta < 0.) delta = 0.;
		return delta;
	}

	inline static bool weight_compare(const E &lhs, const E &rhs) {
		return lhs.get_weight() < rhs.get_weight();
	}

private:
	size_t num_events;
	size_t max_events;
	int period;
	treap_t treap;
};

}}  /* namespace ioremap::monitor */

#endif // EVENT_STATS_HPP
