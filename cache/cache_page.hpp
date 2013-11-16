#ifndef CACHE_PAGE_HPP
#define CACHE_PAGE_HPP

#include "cache.hpp"

namespace ioremap { namespace cache {

class cache_page_t;

class cache_page_t
{
    public:
        cache_page_t(struct dnet_node *n, size_t max_size);

        ~cache_page_t();

        void set_hotter_page(cache_page_t *hotter_page);

        void set_colder_page(cache_page_t *colder_page);

        // Adds new record to page
        int add(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data, elliptics_unique_lock<std::mutex> &guard);

        // Updates existing record in page
        int update(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data, elliptics_unique_lock<std::mutex> &guard);

        std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io, elliptics_unique_lock<std::mutex> &guard);

        int remove(const unsigned char *id, dnet_io_attr *io, elliptics_unique_lock<std::mutex> &guard);

        int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, elliptics_unique_lock<std::mutex> &guard);

        bool contains(const unsigned char *id) const;

        void insert(const unsigned char *id, data_t *obj);

        void life_check(elliptics_unique_lock<std::mutex> &guard);

    private:
        struct dnet_node *m_node;
        size_t m_cache_size, m_max_cache_size;
        iset_t m_set;
        lru_list_t m_lru;
        life_set_t m_lifeset;
        sync_set_t m_syncset;
        cache_page_t *m_colder_page, *m_hotter_page;

        cache_page_t(const cache_page_t &) = delete;

        void move_to_page(cache_page_t *target_page, const unsigned char *id);

        iset_t::iterator create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk);

        iset_t::iterator insert_data(const unsigned char *id, data_t *data);

        iset_t::iterator populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err);

        void resize(size_t reserve);

        void erase_element(data_t *obj);

        void delete_element(data_t *obj);

        void sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp);

        void sync_element(data_t *obj);

        void sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj);
};

}}

#endif // CACHE_PAGE_HPP
