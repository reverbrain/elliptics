#ifndef SLRU_CACHE_HPP
#define SLRU_CACHE_HPP

#include "cache.hpp"
#include "cache_page.hpp"

namespace ioremap { namespace cache {

class slru_cache_t {
    public:
        slru_cache_t(struct dnet_node *n, const std::vector<size_t>& pages_max_sizes);

        ~slru_cache_t();

        void stop();

        int write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data);

        std::shared_ptr<raw_data_t> read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io);

        int remove(const unsigned char *id, dnet_io_attr *io);

        int lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd);

    private:
        bool m_need_exit;
        struct dnet_node *m_node;
        std::mutex m_lock;
        std::vector< std::unique_ptr<cache_page_t> > m_cache_pages;
        std::thread m_lifecheck;

        slru_cache_t(const slru_cache_t &) = delete;

        void life_check(void);
};

}}


#endif // SLRU_CACHE_HPP
