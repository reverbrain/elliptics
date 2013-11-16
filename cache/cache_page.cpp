#include "cache_page.hpp"

#include <deque>

namespace ioremap { namespace cache {

// public:

cache_page_t::cache_page_t(struct dnet_node *n, size_t max_size) :
m_node(n),
m_cache_size(0),
m_max_cache_size(max_size),
m_colder_page(NULL),
m_hotter_page(NULL) {
}

cache_page_t::~cache_page_t() {
    m_max_cache_size = 0; //sets max_size to 0 for erasing lru set
    resize(0);

    while(!m_syncset.empty()) { //removes datas from syncset
        erase_element(&*m_syncset.begin());
    }

    while(!m_lifeset.empty()) { //removes datas from lifeset
        erase_element(&*m_lifeset.begin());
    }
}

void cache_page_t::set_hotter_page(cache_page_t *hotter_page)
{
    m_hotter_page = hotter_page;
}

void cache_page_t::set_colder_page(cache_page_t *colder_page)
{
    m_colder_page = colder_page;
}

int cache_page_t::add(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data, elliptics_unique_lock<std::mutex> &guard) {
    const bool remove_from_disk = (io->flags & DNET_IO_FLAGS_CACHE_REMOVE_FROM_DISK);
    const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
    const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
    const bool append = (io->flags & DNET_IO_FLAGS_APPEND);

    elliptics_timer timer;

    iset_t::iterator it = m_set.find(id);

    if (!cache) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not a cache call\n", dnet_dump_id_str(id));
        return -ENOTSUP;
    }

    // Optimization for append-only commands
    if (!cache_only) {
        if (append) {
            it = create_data(id, 0, 0, false);
            it->set_only_append(true);
            it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
            m_syncset.insert(*it);

            auto &raw = it->data()->data();

            m_cache_size -= raw.size();
            m_lru.erase(m_lru.iterator_to(*it));

            const size_t new_size = raw.size() + io->size;

            timer.restart();

            if (m_cache_size + new_size > m_max_cache_size) {
                dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called\n", dnet_dump_id_str(id));
                resize(new_size * 2);
                dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished: %lld ms\n", dnet_dump_id_str(id), timer.restart());
            }

            m_lru.push_back(*it);
            m_cache_size += new_size;

            raw.insert(raw.end(), data, data + io->size);

            it->set_timestamp(io->timestamp);
            it->set_user_flags(io->user_flags);

            cmd->flags &= ~DNET_FLAGS_NEED_ACK;
            return dnet_send_file_info_ts_without_fd(st, cmd, data, io->size, &io->timestamp);
        }
    }

    if (it == m_set.end()) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: not exist\n", dnet_dump_id_str(id));
        // If file not found and CACHE flag is not set - fallback to backend request
        if (!cache_only && io->offset != 0) {
            int err = 0;
            it = populate_from_disk(guard, id, remove_from_disk, &err);

            if (err != 0 && err != -ENOENT)
                return err;
        }

        // Create empty data for code simplifyng
        if (it == m_set.end()) {
            it = create_data(id, 0, 0, remove_from_disk);
        }
    } else {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: exists\n", dnet_dump_id_str(id));
    }
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data ensured: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    return update(id, st, cmd, io, data, guard);
}

int cache_page_t::update(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, dnet_io_attr *io, const char *data, elliptics_unique_lock<std::mutex> &guard)
{
    const size_t lifetime = io->start;
    const size_t size = io->size;
    const bool append = (io->flags & DNET_IO_FLAGS_APPEND);
    (void) guard;

    elliptics_timer timer;

    iset_t::iterator it = m_set.find(id);

    raw_data_t &raw = *it->data();

    if (io->flags & DNET_IO_FLAGS_COMPARE_AND_SWAP) {
        // Data is already in memory, so it's free to use it
        // raw.size() is zero only if there is no such file on the server
        if (raw.size() != 0) {
            struct dnet_raw_id csum;
            dnet_transform_node(m_node, raw.data().data(), raw.size(), csum.id, sizeof(csum.id));

            if (memcmp(csum.id, io->parent, DNET_ID_SIZE)) {
                dnet_log(m_node, DNET_LOG_ERROR, "%s: cas: cache checksum mismatch\n", dnet_dump_id(&cmd->id));
                return -EBADFD;
            }
        }
    }

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: CAS checked: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    size_t new_size = 0;

    if (append) {
        new_size = raw.size() + size;
    } else {
        new_size = io->offset + io->size;
    }

    // Recalc used space, free enough space for new data, move object to the end of the queue
    m_cache_size -= raw.size();
    m_lru.erase(m_lru.iterator_to(*it));

    if (m_cache_size + new_size > m_max_cache_size) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called: %lld ms\n", dnet_dump_id_str(id), timer.restart());
        resize(new_size * 2);
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished: %lld ms\n", dnet_dump_id_str(id), timer.restart());
    }

    m_lru.push_back(*it);
    it->set_remove_from_cache(false);
    m_cache_size += new_size;

    if (append) {
        raw.data().insert(raw.data().end(), data, data + size);
    } else {
        raw.data().resize(new_size);
        memcpy(raw.data().data() + io->offset, data, size);
    }

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: data modified: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    // Mark data as dirty one, so it will be synced to the disk
    if (!it->synctime() && !(io->flags & DNET_IO_FLAGS_CACHE_ONLY)) {
        it->set_synctime(time(NULL) + m_node->cache_sync_timeout);
        m_syncset.insert(*it);
    }

    if (it->lifetime())
        m_lifeset.erase(m_lifeset.iterator_to(*it));

    if (lifetime) {
        it->set_lifetime(lifetime + time(NULL));
        m_lifeset.insert(*it);
    }

    it->set_timestamp(io->timestamp);
    it->set_user_flags(io->user_flags);

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: finished write: %lld ,s\n", dnet_dump_id_str(id), timer.restart());

    cmd->flags &= ~DNET_FLAGS_NEED_ACK;
    return dnet_send_file_info_ts_without_fd(st, cmd, raw.data().data() + io->offset, io->size, &io->timestamp);
}

std::shared_ptr<raw_data_t> cache_page_t::read(const unsigned char *id, dnet_cmd *cmd, dnet_io_attr *io, elliptics_unique_lock<std::mutex> &guard) {
    const bool cache = (io->flags & DNET_IO_FLAGS_CACHE);
    const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
    (void) cmd;

    elliptics_timer timer;

    iset_t::iterator it = m_set.find(id);
    if (it != m_set.end() && it->only_append()) {
        sync_after_append(guard, true, &*it);
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: synced append-only data, find+sync: %lld ms\n", dnet_dump_id_str(id), timer.restart());

        it = m_set.end();
    }
    timer.restart();

    if (it == m_set.end() && cache && !cache_only) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: not exist\n", dnet_dump_id_str(id));
        int err = 0;
        it = populate_from_disk(guard, id, false, &err);
    } else {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: exists\n", dnet_dump_id_str(id));
    }

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: data ensured: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    if (it != m_set.end()) {
        io->timestamp = it->timestamp();
        io->user_flags = it->user_flags();

        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE READ: returned: %lld ms\n", dnet_dump_id_str(id), timer.restart());

        std::shared_ptr<raw_data_t> result(it->data());

        move_to_page(m_hotter_page, id);

        return result;
    }

    return std::shared_ptr<raw_data_t>();
}

int cache_page_t::remove(const unsigned char *id, dnet_io_attr *io, elliptics_unique_lock<std::mutex> &guard) {
    const bool cache_only = (io->flags & DNET_IO_FLAGS_CACHE_ONLY);
    bool remove_from_disk = !cache_only;
    int err = -ENOENT;

    elliptics_timer timer;

    iset_t::iterator it = m_set.find(id);

    if (it != m_set.end()) {
        // If cache_only is not set the data also should be remove from the disk
        // If data is marked and cache_only is not set - data must be synced to the disk
        remove_from_disk |= it->remove_from_disk();
        if (it->synctime() && !cache_only) {
            m_syncset.erase(m_syncset.iterator_to(*it));
            it->clear_synctime();
        }
        erase_element(&(*it));
        err = 0;
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: erased: %lld ms\n", dnet_dump_id_str(id), timer.restart());
    }

    guard.unlock();

    if (remove_from_disk) {
        struct dnet_id raw;
        memset(&raw, 0, sizeof(struct dnet_id));

        dnet_setup_id(&raw, 0, (unsigned char *)id);

        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: before removing from disk\n", dnet_dump_id_str(id));
        timer.restart();
        int local_err = dnet_remove_local(m_node, &raw);
        if (local_err != -ENOENT)
            err = local_err;
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE REMOVE: after removing from disk: %lld ms\n", dnet_dump_id_str(id), timer.restart());
    }

    return err;
}

int cache_page_t::lookup(const unsigned char *id, dnet_net_state *st, dnet_cmd *cmd, elliptics_unique_lock<std::mutex> &guard) {
    int err = 0;

    iset_t::iterator it = m_set.find(id);
    if (it == m_set.end()) {
        return -ENOTSUP;
    }

    dnet_time timestamp = it->timestamp();

    guard.unlock();

    local_session sess(m_node);

    cmd->flags |= DNET_FLAGS_NOCACHE;

    ioremap::elliptics::data_pointer data = sess.lookup(*cmd, &err);

    cmd->flags &= ~DNET_FLAGS_NOCACHE;

    if (err) {
        cmd->flags &= ~DNET_FLAGS_NEED_ACK;
        return dnet_send_file_info_ts_without_fd(st, cmd, NULL, 0, &timestamp);
    }

    dnet_file_info *info = data.skip<dnet_addr>().data<dnet_file_info>();
    info->mtime = timestamp;

    cmd->flags &= (DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);
    return dnet_send_reply(st, cmd, data.data(), data.size(), 0);
}

bool cache_page_t::contains(const unsigned char *id) const {
    return m_set.find(id) != m_set.end();
}

void cache_page_t::insert(const unsigned char *id, data_t *obj)
{
    iset_t::iterator it = insert_data(id, obj);

    if (obj->synctime()) {
        m_syncset.insert(*it);
    }
    if (obj->lifetime()) {
        m_lifeset.insert(*it);
    }
}

void cache_page_t::move_to_page(cache_page_t *target_page, const unsigned char *id) {
    iset_t::iterator it = m_set.find(id);
    data_t *obj = &*it;
    if (target_page) {
        erase_element(obj);
        target_page->insert(id, obj);
    } else {
        delete_element(obj);
    }
}

// private:

iset_t::iterator cache_page_t::create_data(const unsigned char *id, const char *data, size_t size, bool remove_from_disk) {
    if (m_cache_size + size > m_max_cache_size) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called from create_data\n", dnet_dump_id_str(id));
        resize(size);
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished from create_data\n", dnet_dump_id_str(id));
    }

    data_t *raw = new data_t(id, 0, data, size, remove_from_disk);

    m_cache_size += size;

    m_lru.push_back(*raw);
    return m_set.insert(*raw).first;
}

iset_t::iterator cache_page_t::insert_data(const unsigned char *id, data_t *raw) {
    size_t size = raw->size();
    if (m_cache_size + size > m_max_cache_size) {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize called from create_data\n", dnet_dump_id_str(id));
        resize(size);
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: resize finished from create_data\n", dnet_dump_id_str(id));
    }

    m_cache_size += size;

    m_lru.push_back(*raw);
    return m_set.insert(*raw).first;
}

iset_t::iterator cache_page_t::populate_from_disk(elliptics_unique_lock<std::mutex> &guard, const unsigned char *id, bool remove_from_disk, int *err) {
    if (guard.owns_lock()) {
        guard.unlock();
    }

    elliptics_timer timer;

    local_session sess(m_node);
    sess.set_ioflags(DNET_IO_FLAGS_NOCACHE);

    dnet_id raw_id;
    memset(&raw_id, 0, sizeof(raw_id));
    memcpy(raw_id.id, id, DNET_ID_SIZE);

    uint64_t user_flags = 0;
    dnet_time timestamp;
    dnet_empty_time(&timestamp);

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk started: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    ioremap::elliptics::data_pointer data = sess.read(raw_id, &user_flags, &timestamp, err);

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk finished: %lld ms, err: %d\n", dnet_dump_id_str(id), timer.restart(), *err);

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, before lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());
    guard.lock();
    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, after lock: %lld ms\n", dnet_dump_id_str(id), timer.restart());

    if (*err == 0) {
        auto it = create_data(id, reinterpret_cast<char *>(data.data()), data.size(), remove_from_disk);
        it->set_user_flags(user_flags);
        it->set_timestamp(timestamp);
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: populating from disk, data created: %lld ms\n", dnet_dump_id_str(id), timer.restart());
        return it;
    }

    return m_set.end();
}

void cache_page_t::resize(size_t reserve) {
    size_t removed_size = 0;

    for (auto it = m_lru.begin(); it != m_lru.end();) {
        if (m_max_cache_size + removed_size > m_cache_size + reserve)
            break;

        data_t *raw = &*it;
        ++it;

        if (raw->synctime() || raw->remove_from_cache()) {
            if (!raw->remove_from_cache()) {
                raw->set_remove_from_cache(true);

                m_syncset.erase(m_syncset.iterator_to(*raw));
                raw->set_synctime(1);
                m_syncset.insert(*raw);
            }
            removed_size += raw->size();
        } else {
            move_to_page(m_colder_page, raw->id().id);
        }
    }
}

void cache_page_t::erase_element(data_t *obj) {
    elliptics_timer timer;

    m_lru.erase(m_lru.iterator_to(*obj));
    m_set.erase(m_set.iterator_to(*obj));
    if (obj->lifetime()) {
        m_lifeset.erase(m_lifeset.iterator_to(*obj));
        obj->set_lifetime(0);
    }

    if (obj->synctime()) {
        m_syncset.erase(m_syncset.iterator_to(*obj));
        obj->clear_synctime();
    }

    m_cache_size -= obj->size();

    dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: erased element: %lld ms\n", dnet_dump_id_str(obj->id().id), timer.restart());
}

void cache_page_t::delete_element(data_t *obj)
{
    if (obj->synctime()) {
        sync_element(obj);
    }
    erase_element(obj);
    delete obj;
}

void cache_page_t::sync_element(const dnet_id &raw, bool after_append, const std::vector<char> &data, uint64_t user_flags, const dnet_time &timestamp) {
    local_session sess(m_node);
    sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | (after_append ? DNET_IO_FLAGS_APPEND : 0));

    int err = sess.write(raw, data.data(), data.size(), user_flags, timestamp);
    if (err) {
        dnet_log(m_node, DNET_LOG_ERROR, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
    } else {
        dnet_log(m_node, DNET_LOG_DEBUG, "%s: CACHE: forced to sync to disk, err: %d\n", dnet_dump_id_str(raw.id), err);
    }
}

void cache_page_t::sync_element(data_t *obj) {
    struct dnet_id raw;
    memset(&raw, 0, sizeof(struct dnet_id));
    memcpy(raw.id, obj->id().id, DNET_ID_SIZE);

    auto &data = obj->data()->data();

    sync_element(raw, obj->only_append(), data, obj->user_flags(), obj->timestamp());
}

void cache_page_t::sync_after_append(elliptics_unique_lock<std::mutex> &guard, bool lock_guard, data_t *obj) {
    elliptics_timer timer;

    std::shared_ptr<raw_data_t> raw_data = obj->data();
    m_syncset.erase(m_syncset.iterator_to(*obj));
    obj->set_synctime(0);

    dnet_id id;
    memset(&id, 0, sizeof(id));
    memcpy(id.id, obj->id().id, DNET_ID_SIZE);

    uint64_t user_flags = obj->user_flags();
    dnet_time timestamp = obj->timestamp();

    const auto timer_prepare = timer.restart();

    erase_element(&*obj);

    const auto timer_erase = timer.restart();

    guard.unlock();

    local_session sess(m_node);
    sess.set_ioflags(DNET_IO_FLAGS_NOCACHE | DNET_IO_FLAGS_APPEND);

    auto &raw = raw_data->data();

    const auto timer_before_write = timer.restart();

    int err = sess.write(id, raw.data(), raw.size(), user_flags, timestamp);

    const auto timer_after_write = timer.restart();

    if (lock_guard)
        guard.lock();

    const auto timer_lock = timer.restart();

    dnet_log(m_node, DNET_LOG_INFO, "%s: CACHE: sync after append, "
        "prepare: %lld ms, erase: %lld ms, before_write: %lld ms, after_write: %lld ms, lock: %lld ms, err: %d",
         dnet_dump_id_str(id.id), timer_prepare, timer_erase, timer_before_write, timer_after_write, timer_lock, err);
}

void cache_page_t::life_check(elliptics_unique_lock<std::mutex> &guard) {
    std::deque<struct dnet_id> remove;

    while (!m_lifeset.empty()) {
        size_t time = ::time(NULL);

        if (m_lifeset.empty())
            break;

        life_set_t::iterator it = m_lifeset.begin();
        if (it->lifetime() > time)
            break;

        if (it->remove_from_disk()) {
            struct dnet_id id;
            memset(&id, 0, sizeof(struct dnet_id));

            dnet_setup_id(&id, 0, (unsigned char *)it->id().id);

            remove.push_back(id);
        }

        delete_element(&(*it));
    }

    dnet_id id;
    std::vector<char> data;
    uint64_t user_flags;
    dnet_time timestamp;

    memset(&id, 0, sizeof(id));

    while (!m_syncset.empty()) {
        size_t time = ::time(NULL);

        if (m_syncset.empty())
            break;

        sync_set_t::iterator it = m_syncset.begin();

        data_t *obj = &*it;
        if (obj->synctime() > time)
            break;

        if (obj->only_append()) {
            sync_after_append(guard, false, obj);
            continue;
        }

        memcpy(id.id, obj->id().id, DNET_ID_SIZE);
        data = it->data()->data();
        user_flags = obj->user_flags();
        timestamp = obj->timestamp();

        m_syncset.erase(it);
        obj->clear_synctime();

        guard.unlock();
        dnet_oplock(m_node, &id);

        // sync_element uses local_session which always uses DNET_FLAGS_NOLOCK
        sync_element(id, false, data, user_flags, timestamp);

        dnet_opunlock(m_node, &id);
        guard.lock();

        auto jt = m_set.find(id.id);
        if (jt != m_set.end()) {
            if (jt->remove_from_cache()) {
                erase_element(&*jt);
            }
        }
    }

    for (std::deque<struct dnet_id>::iterator it = remove.begin(); it != remove.end(); ++it) {
        dnet_remove_local(m_node, &(*it));
    }
}

}}
