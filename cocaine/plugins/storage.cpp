/*
    Copyright (c) 2011-2012 Andrey Sibiryov <me@kobology.ru>
    Copyright (c) 2011-2012 Other contributors as noted in the AUTHORS file.

    This file is part of Cocaine.

    Cocaine is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    Cocaine is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "storage.hpp"

#include <cocaine/context.hpp>
#include <cocaine/logging.hpp>

using namespace cocaine;
using namespace cocaine::logging;
using namespace cocaine::storage;

log_adapter_impl_t::log_adapter_impl_t(const std::shared_ptr<logging::log_t> &log):
    m_log(log)
{
}

void
log_adapter_impl_t::log(const int level,
                        const char *message)
{
    switch(level) {
        case DNET_LOG_DEBUG:
            COCAINE_LOG_DEBUG(m_log, "%s", message);
            break;

        case DNET_LOG_NOTICE:
            COCAINE_LOG_INFO(m_log, "%s", message);
            break;

        case DNET_LOG_INFO:
            COCAINE_LOG_INFO(m_log, "%s", message);
            break;

        case DNET_LOG_ERROR:
            COCAINE_LOG_ERROR(m_log, "%s", message);
            break;

        default:
            break;
    };
}

log_adapter_t::log_adapter_t(const std::shared_ptr<logging::log_t>& log,
                             const int level):
    ioremap::elliptics::logger(new log_adapter_impl_t(log), level)
{ }

namespace {
    struct digitizer {
        template<class T>
        int
        operator()(const T& value) {
            return value.asInt();
        }
    };
}

elliptics_storage_t::elliptics_storage_t(context_t& context,
                                         const std::string& name,
                                         const Json::Value& args):
    category_type(context, name, args),
    m_context(context),
    m_log(new log_t(context, name)),
    m_log_adapter(m_log, args.get("verbosity", DNET_LOG_ERROR).asUInt()),
    m_node(m_log_adapter),
    m_session(m_node)
{
    Json::Value nodes(args["nodes"]);

    if(nodes.empty() || !nodes.isObject()) {
        throw configuration_error_t("no nodes has been specified");
    }

    Json::Value::Members node_names(nodes.getMemberNames());

    bool have_remotes = false;

    for(Json::Value::Members::const_iterator it = node_names.begin();
        it != node_names.end();
        ++it)
    {
        try {
            m_node.add_remote(
                it->c_str(),
                nodes[*it].asInt()
            );
            have_remotes = true;
        } catch(const ioremap::elliptics::error& e) {
            // Do nothing. Yes. Really. We only care if no remote nodes were added at all.
        }
    }

    if (!have_remotes) {
        throw configuration_error_t("can not connect to any remote node");
    }

    Json::Value groups(args["groups"]);

    if(groups.empty() || !groups.isArray()) {
        throw configuration_error_t("no groups has been specified");
    }

    std::transform(
        groups.begin(),
        groups.end(),
        std::back_inserter(m_groups),
        digitizer()
    );

    m_session.set_groups(m_groups);
}

std::string
elliptics_storage_t::read(const std::string& collection,
                          const std::string& key)
{
    std::string blob;

    COCAINE_LOG_DEBUG(
        m_log,
        "reading the '%s' object, collection: '%s'",
        key,
        collection
    );

    try {
	blob = m_session.read_data(id(collection, key), 0, 0).get_one().file().to_string();
    } catch(const ioremap::elliptics::error& e) {
        throw storage_error_t(e.what());
    }

    return blob;
}

void
elliptics_storage_t::write(const std::string& collection,
                           const std::string& key,
                           const std::string& blob)
{
    struct dnet_id dnet_id;
    struct timespec ts = { 0, 0 };

    // NOTE: Elliptcs does not initialize the contents of the keys.
    memset(&dnet_id, 0, sizeof(struct dnet_id));

    COCAINE_LOG_DEBUG(
        m_log,
        "writing the '%s' object, collection: '%s'",
        key,
        collection
    );

    try {
        // Generate the key.
        m_session.transform(
            id(collection, key),
            dnet_id
        );

        // Write the blob.
        m_session.write_data(dnet_id, blob, 0);

        // Write the blob metadata.
        m_session.write_metadata(
            dnet_id,
            id(collection, key),
            m_groups,
            ts
        );

        // Check if the key already exists in the collection.
        std::vector<std::string> keylist(
            list(collection)
        );

        if(std::find(keylist.begin(), keylist.end(), key) == keylist.end()) {
            msgpack::sbuffer buffer;
            std::string object;

            keylist.push_back(key);
            msgpack::pack(&buffer, keylist);

            object.assign(
                buffer.data(),
                buffer.size()
            );

            // Generate the collection object key.
            m_session.transform(
                id("system", "list:" + collection),
                dnet_id
            );

            // Update the collection object.
            m_session.write_data(dnet_id, object, 0);

            // Update the collection object metadata.
            m_session.write_metadata(
                dnet_id,
                id("system", "list:" + collection),
                m_groups,
                ts
            );
        }
    } catch(const ioremap::elliptics::error& e) {
        throw storage_error_t(e.what());
    }
}

std::vector<std::string>
elliptics_storage_t::list(const std::string& collection) {
    std::vector<std::string> result;
    std::string blob;

    try {
        blob = m_session.read_data(id("system", "list:" + collection), 0, 0).get_one().file().to_string();
    } catch(const ioremap::elliptics::error& e) {
        return result;
    }

    msgpack::unpacked unpacked;

    try {
        msgpack::unpack(&unpacked, blob.data(), blob.size());
        unpacked.get().convert(&result);
    } catch(const msgpack::unpack_error& e) {
        throw storage_error_t("the collection metadata is corrupted");
    } catch(const msgpack::type_error& e) {
        throw storage_error_t("the collection metadata is corrupted");
    }

    return result;
}

void
elliptics_storage_t::remove(const std::string& collection,
                            const std::string& key)
{
    struct dnet_id dnet_id;
    struct timespec ts = { 0, 0 };

    // NOTE: Elliptcs does not initialize the contents of the keys.
    memset(&dnet_id, 0, sizeof(struct dnet_id));

    COCAINE_LOG_DEBUG(
        m_log,
        "removing the '%s' object, collection: '%s'",
        key,
        collection
    );

    try {
        std::vector<std::string> keylist(list(collection)),
                                 updated;

        std::remove_copy(
            keylist.begin(),
            keylist.end(),
            std::back_inserter(updated),
            key
        );

        msgpack::sbuffer buffer;
        std::string object;

        msgpack::pack(&buffer, updated);
        object.assign(buffer.data(), buffer.size());

        // Generate the collection object key.
        m_session.transform(
            id("system", "list:" + collection),
            dnet_id
        );

        // Update the collection object.
        m_session.write_data(dnet_id, object, 0);

        // Update the collection object metadata.
        m_session.write_metadata(
            dnet_id,
            id("system", "list:" + collection),
            m_groups,
            ts
        );

        // Remove the actual key.
        m_session.remove(id(collection, key));
    } catch(const ioremap::elliptics::error& e) {
        throw storage_error_t(e.what());
    }
}
