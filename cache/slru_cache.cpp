#include "slru_cache.hpp"

namespace ioremap { namespace cache {

// public:

slru_cache_t::slru_cache_t(struct dnet_node *n, const std::vector<size_t> &pages_max_sizes) :
m_need_exit(false),
m_node(n) {
    // Page[0] is the hottest
    for (size_t page_max_size : pages_max_sizes) {
        m_cache_pages.emplace_back(std::unique_ptr<cache_page_t>(new cache_page_t(n, page_max_size)));
    }

    for (size_t i = 0; i < m_cache_pages.size(); ++i) {
        if (i + 1 < m_cache_pages.size()) {
            m_cache_pages[i]->set_colder_page(m_cache_pages[i + 1].get());
        }

        if (i > 0) {
            m_cache_pages[i]->set_hotter_page(m_cache_pages[i - 1].get());
        }
    }
    m_cache_pages[0]->set_hotter_page(m_cache_pages[0].get());

    m_lifecheck = std::thread(std::bind(&slru_cache_t::life_check, this));
}

slru_cache_t::~slru_cache_t() {
    stop();
    m_lifecheck.join();

    elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "~cache_t: %p", this);
}

void slru_cache_t::stop() {
    m_need_exit = true;
}

int slru_cache_t::write(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data) {

    elliptics_timer timer;

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: before guard\n", dnet_dump_id_str(id));
    elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE WRITE: %p", dnet_dump_id_str(id), this);
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    for (size_t i = 0; i < m_cache_pages.size(); ++i) {
        if (m_cache_pages[i]->contains(id)) {
            return m_cache_pages[i]->update(id, st, cmd, io, data, guard);
        }
    }
    return m_cache_pages.back()->add(id, st, cmd, io, data, guard);
}

std::shared_ptr<raw_data_t> slru_cache_t::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io) {
    elliptics_timer timer;

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: before guard\n", dnet_dump_id_str(id));
    elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE READ: %p", dnet_dump_id_str(id), this);
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    for (size_t i = 0; i < m_cache_pages.size(); ++i) {
        if (m_cache_pages[i]->contains(id)) {
            return m_cache_pages[i]->read(id, cmd, io, guard);
        }
    }
    return m_cache_pages.back()->read(id, cmd, io, guard);
}

int slru_cache_t::remove(const unsigned char *id, dnet_io_attr *io) {
    elliptics_timer timer;

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: before guard\n", dnet_dump_id_str(id));
    elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE REMOVE: %p", dnet_dump_id_str(id), this);
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    for (size_t i = 0; i < m_cache_pages.size(); ++i) {
        if (m_cache_pages[i]->contains(id)) {
            return m_cache_pages[i]->remove(id, io, guard);
        }
    }
    return m_cache_pages.back()->remove(id, io, guard);
}

int slru_cache_t::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd) {
    elliptics_timer timer;

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE LOOKUP: before guard\n", dnet_dump_id_str(id));
    elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "%s: CACHE LOOKUP: %p", dnet_dump_id_str(id), this);
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE LOOKUP: after guard, lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    for (size_t i = 0; i < m_cache_pages.size(); ++i) {
        if (m_cache_pages[i]->contains(id)) {
            return m_cache_pages[i]->lookup(id, st, cmd, guard);
        }
    }
    return m_cache_pages.back()->lookup(id, st, cmd, guard);
}

// private:

void slru_cache_t::life_check(void) {
    while (!m_need_exit) {

        for (size_t i = 0; i < m_cache_pages.size(); ++i) {
            elliptics_unique_lock<std::mutex> guard(m_lock, m_node, "CACHE LIFE: %p", this);
            m_cache_pages[i]->life_check(guard);
        }
        sleep(1);
    }
}

}}
