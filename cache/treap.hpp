/*
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

#ifndef TREAP_HPP
#define TREAP_HPP

#include <stdexcept>

namespace ioremap { namespace cache {

template<typename T>
class treap_node_traits {};

template<typename T>
class treap_node_t {
public:
	// type traits
	typedef typename treap_node_traits<T>::key_type key_type;
	typedef typename treap_node_traits<T>::priority_type priority_type;

	treap_node_t(): l(NULL), r(NULL) {}

	// node policy
	key_type get_key() const;
	priority_type get_priority() const;
	static int key_compare(const key_type &lhs, const key_type &rhs);
	static int priority_compare(const priority_type &lhs, const priority_type &rhs);

	T *l;
	T *r;
};

template<typename node_type>
class treap {

public:
	typedef node_type* p_node_type;
	typedef typename node_type::priority_type priority_type;
	typedef typename node_type::key_type key_type;

	treap(): root(NULL) {
	}

	~treap() {
		cleanup(root);
	}

	void insert(p_node_type node) {
		if (!node) {
			throw std::logic_error("insert: can't insert NULL");
		}
		node->l = NULL;
		node->r = NULL;
		if (empty())
			root = node;
		else
			insert(root, node);
	}

	p_node_type find(const key_type& key) const {
		if (empty()) {
			return NULL;
		}
		return find(root, key);
	}

	void erase(const key_type& key) {
		if (empty()) {
			throw std::logic_error("erase: element does not exist");
		}
		erase(root, key);
	}

	void erase(p_node_type node) {
		if (empty()) {
			throw std::logic_error("erase: element does not exist");
		}
		erase(get_key(node));
	}

	void decrease_key(p_node_type node) {
		erase(node);
		insert(node);
	}

	p_node_type top() const {
		return root;
	}

	bool empty() const {
		return !root;
	}

private:

	key_type get_key(p_node_type node) const {
		if (!node) {
			throw std::logic_error("getKey: node is NULL");
		}
		return node->get_key();
	}

	priority_type get_priority(p_node_type node) const {
		if (!node) {
			throw std::logic_error("getPriority: node is NULL");
		}
		return node->get_priority();
	}

	inline int key_compare(const key_type& lhs, const key_type& rhs) const {
		return node_type::key_compare(lhs, rhs);
	}

	inline int priority_compare(const priority_type& lhs, const priority_type& rhs) const {
		return node_type::priority_compare(lhs, rhs);
	}

	void cleanup(p_node_type t) {
		if (t) {
			cleanup(t->l);
			cleanup(t->r);
			delete t;
		}
	}

	void split(p_node_type t, key_type key, p_node_type & l, p_node_type & r) {
		if (!t) {
			l = NULL;
			r = NULL;
		}
		else if (key_compare(key, get_key(t)) < 0) {
			split(t->l, key, l, t->l);
			r = t;
		}
		else {
			split(t->r, key, t->r, r);
			l = t;
		}
	}

	void insert(p_node_type & t, p_node_type it) {
		if (!t) {
			t = it;
		}
		else {
			int cmp_result = priority_compare(get_priority(it), get_priority(t));
			if (cmp_result == 0) {
				cmp_result = rand() & 1 ? 1 : -1;
			}
			if (cmp_result > 0) {
				split(t, get_key(it), it->l, it->r);
				t = it;
			}
			else {
				insert((key_compare(get_key(it), get_key(t)) < 0) ? t->l : t->r, it);
			}
		}
	}

	void merge(p_node_type & t, p_node_type l, p_node_type r) {
		if (!l || !r) {
			t = l ? l : r;
		}
		else {
			int cmp_result = priority_compare(get_priority(l), get_priority(r));
			if (cmp_result == 0) {
				cmp_result = rand() & 1 ? 1 : -1;
			}

			if (cmp_result > 0) {
				merge(l->r, l->r, r);
				t = l;
			}
			else {
				merge(r->l, l, r->l);
				t = r;
			}
		}
	}

	void erase (p_node_type & t, const key_type& key) {
		if (!t) {
			throw std::logic_error("erase: element does not exist");
		}

		int cmp_result = key_compare(get_key(t), key);
		if (cmp_result == 0) {
			merge(t, t->l, t->r);
		}
		else {
			erase((cmp_result > 0) ? t->l : t->r, key);
		}
	}

	p_node_type find(p_node_type t, const key_type& key, int depth = 0) const {
		if (!t) {
			return NULL;
		}

		int cmp_result = key_compare(get_key(t), key);
		if (cmp_result == 0) {
			return t;
		}

		if (cmp_result > 0) {
			return find(t->l, key, depth + 1);
		}
		else {
			return find(t->r, key, depth + 1);
		}
	}

	p_node_type root;
};

}}

#endif // TREAP_HPP
