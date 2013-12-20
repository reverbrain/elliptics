#ifndef TREAP_HPP
#define TREAP_HPP

#include "cache.hpp"
#include <stdexcept>
#include <unordered_set>

namespace ioremap { namespace cache {

template<typename T>
class treap_node_t {
public:
	treap_node_t(): l(NULL), r(NULL) {}
	T *l;
	T *r;
};

struct data_t;

template<typename node_type>
class treap {

public:
	typedef node_type* p_node_type;
	typedef const unsigned char * key_type;
	typedef size_t priority_type;

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
		return node->id().id;
	}

	priority_type get_priority(p_node_type node) const {
		if (!node) {
			throw std::logic_error("getPriority: node is NULL");
		}
		return node->eventtime();
	}

	inline int key_compare(const key_type& lhs, const key_type& rhs) const {
		return dnet_id_cmp_str(lhs, rhs);
	}

	inline int priority_compare(const priority_type& lhs, const priority_type& rhs) const {
		if (lhs < rhs) {
			return 1;
		}

		if (lhs > rhs) {
			return -1;
		}

		return 0;
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
