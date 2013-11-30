#ifndef TREAP_HPP
#define TREAP_HPP

#include "cache.hpp"

namespace ioremap { namespace cache {

template<typename T>
class treap_node_t {
public:
    treap_node_t(): l(NULL), r(NULL) {}
    T *l;
    T *r;
};

template<typename NodeType>
class Treap {

public:
    typedef NodeType* PNodeType;
    typedef const unsigned char * KeyType;
    typedef size_t PriorityType;

    Treap(): root(NULL) {
    }

    ~Treap() {
        cleanup(root);
    }

    void insert(PNodeType node) {
        if (!root)
            root = node;
        else
            insert(root, node);
    }

    PNodeType find(const KeyType& key) const {
        return find(root, key);
    }

    void erase(const KeyType& key) {
        erase(root, key);
    }

    void erase(PNodeType node) {
        erase(getKey(*node));
    }

    PNodeType top() const {
        return root;
    }

    bool empty() const {
        return !root;
    }

private:

    KeyType getKey(PNodeType node) const {
        return node->id().id;
    }

    const PriorityType& getPriority(PNodeType node) const {
        return node->eventtime();
    }

    inline int keyCompare(const KeyType& lhs, const KeyType& rhs) const {
        return dnet_id_cmp_str(lhs, rhs);
    }

    inline int priorityCompare(const PriorityType& lhs, const PriorityType& rhs) const {
        if (lhs < rhs)
            return -1;

        if (lhs > rhs)
            return 1;

        return 0;
    }

    void cleanup(PNodeType t) {
        if (t)
        {
            cleanup(t->l);
            cleanup(t->r);
            delete t;
        }
    }

    void split (PNodeType t, KeyType key, PNodeType & l, PNodeType & r) {
        if (!t)
            l = r = NULL;
        else if (keyCompare(key, getKey(t)) < 0)
            split(t->l, key, l, t->l),  r = t;
        else
            split(t->r, key, t->r, r),  l = t;
    }

    void insert (PNodeType & t, PNodeType it) {
        if (!t)
            t = it;
        else if (priorityCompare(getPriority(it), getPriority(t)) > 0)
            split(t, it->key, it->l, it->r),  t = it;
        else
            insert(it->key < t->key ? t->l : t->r, it);
    }

    void merge (PNodeType & t, PNodeType l, PNodeType r) {
        if (!l || !r)
            t = l ? l : r;
        else if (priorityCompare(getPriority(l), getPriority(r)) > 0)
            merge(l->r, l->r, r),  t = l;
        else
            merge(r->l, l, r->l),  t = r;
    }

    void erase (PNodeType & t, const KeyType& key) {
        if (keyCompare(getKey(t), key) == 0)
            merge(t, t->l, t->r);
        else
            erase((keyCompare(key, getKey(t)) < 0) ? t->l : t->r, key);
    }

    PNodeType find(PNodeType t, const KeyType& key) const {
        if (!t)
            return NULL;

        if (keyCompare(getKey(t), key) == 0)
            return t;

        if (keyCompare(getKey(t), key) > 0)
            return find(t->l, key);
        else
            return find(t->r, key);
    }

    PNodeType root;
};

}}

#endif // TREAP_HPP
