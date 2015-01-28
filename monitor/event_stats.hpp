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

#include <algorithm>
#include <functional> // not1

//#define TOP_SLICES
#define TOP_LRU

#ifdef TOP_LRU

namespace ioremap { namespace monitor {

template<typename E>
class key_stat_t;

}}  /* namespace ioremap::monitor */

namespace ioremap { namespace cache {

template<typename E>
struct treap_node_traits<ioremap::monitor::key_stat_t<E> >
{
	typedef typename E::key_type key_type;
	typedef typename E::time_type priority_type;
};

}}  /* namespace ioremap::cache */

namespace ioremap { namespace monitor {

class mutex_lock_policy
{
	typedef std::mutex mutex_type;
public:
	class unique_lock {
	public:
		unique_lock(mutex_lock_policy *policy)
		: lock_(policy->get_lock())
		{}
	private:
		std::unique_lock<mutex_type> lock_;
	};

	mutex_type &get_lock() { return mut_; }
private:
	mutex_type mut_;
};

class null_lock_policy
{
public:
	class unique_lock {
	public:
		unique_lock(null_lock_policy *policy) { (void) policy; }
	};
};

template<typename E>
class key_stat_t : public ioremap::cache::treap_node_t<key_stat_t<E> > {
public:
	key_stat_t(const E &event) : m_event(std::move(event)) {}

	size_t get_weight() const { return m_event.get_weight(); }

	void update_weight(time_t time, size_t window_size, size_t size) {
		double delta = compute_delta(time, m_event.get_time(), window_size);
		m_event.set_weight(delta * m_event.get_weight() + size);
	}

	void update_frequency(time_t time, size_t window_size, double freq) {
		double delta = compute_delta(time, m_event.get_time(), window_size);
		m_event.set_frequency(delta * m_event.get_frequency() + freq);
	}

	void check_expiration(time_t time, size_t window_size) {
		if (time - m_event.get_time() > window_size)
			m_event.set_weight(0);
	}

	void update_time(time_t time) {
		m_event.set_time(time);
	}

	const E &get_event() const { return m_event; }

	// treap_node_t
	typedef typename ioremap::cache::treap_node_traits<key_stat_t>::key_type key_type;
	typedef typename ioremap::cache::treap_node_traits<key_stat_t>::priority_type priority_type;

	key_type get_key() const {
		return m_event.get_key();
	}

	priority_type get_priority() const {
		return m_event.get_time();
	}

	inline static int key_compare(const key_type &lhs, const key_type &rhs) {
		return E::key_compare(lhs, rhs);
	}

	inline static int priority_compare(const priority_type &lhs, const priority_type &rhs) {
		return E::time_compare(lhs, rhs);
	}

private:
	inline double compute_delta(time_t current_time, time_t last_time, size_t window_size) const {
		double delta = 1. - (current_time - last_time) / (double)window_size;
		if (delta < 0.) delta = 0.;
		return delta;
	}

private:
	E m_event;
};

template<typename E, typename lock_policy = null_lock_policy>
class event_stats : private lock_policy
{
	typedef ioremap::cache::treap< key_stat_t<E> > treap_t;
public:
	event_stats(size_t events_limit, int period_in_seconds)
	: num_events(0),
	 max_events(events_limit),
	 period(period_in_seconds)
	{}

	~event_stats() {
		clear();
	}

	void add_event(const E &event, time_t time)
	{
		typename lock_policy::unique_lock lock(this);
		typename treap_t::p_node_type it = treap.find( reinterpret_cast<typename treap_t::key_type>(event.get_key()) );
		if (it) {
			it->update_weight(time, period, event.size);
			it->update_frequency(time, period, 1.);
			it->update_time(time);
			treap.decrease_key(it);
		} else {
			if (num_events < max_events) {
				treap.insert(new key_stat_t<E>(event));
				++num_events;
			} else {
				typename treap_t::p_node_type t = treap.top();
				treap.erase(t);
				delete t;
				treap.insert(new key_stat_t<E>(event));
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
				n->check_expiration(time, period);
				if ( n->get_weight() == 0 ) {
					treap.erase( n );
					delete n;
					--num_events;
				} else {
					top_size.push_back(n->get_event());
				}
			}
		}

		k = std::min(top_size.size(), k);
		std::function<decltype(E::weight_compare)> comparator_weight(&E::weight_compare);
		std::partial_sort(top_size.begin(), top_size.begin() + k, top_size.end(), std::not2(comparator_weight));
		top_size.resize(k);
	}

private:
	template<typename Container>
	void treap_to_container(const typename treap_t::p_node_type node, Container &container) const {
		if (node) {
			container.push_back(node);
			treap_to_container(node->l, container);
			treap_to_container(node->r, container);
		}
	}

	void clear() {
		while (!treap.empty()) {
			key_stat_t<E> *t = treap.top();
			treap.erase(t);
			delete t;
		}
	}

private:
	size_t num_events;
	size_t max_events;
	int period;
	treap_t treap;
};

}}  /* namespace ioremap::monitor */

#endif // TOP_LRU

#endif // EVENT_STATS_HPP
