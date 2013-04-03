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

#ifndef COCAINE_ELLIPTICS_STORAGE_HPP
#define COCAINE_ELLIPTICS_STORAGE_HPP

#include <cocaine/api/storage.hpp>

#include <elliptics/cppdef.h>

namespace cocaine { namespace storage {

class log_adapter_impl_t:
    public ioremap::elliptics::logger_interface
{
    public:
        log_adapter_impl_t(const std::shared_ptr<logging::log_t>& log);

        virtual void log(const int level, const char *msg);

    private:
        std::shared_ptr<logging::log_t> m_log;
};

class log_adapter_t:
    public ioremap::elliptics::logger
{
    public:
        log_adapter_t(const std::shared_ptr<logging::log_t>& log,
                      const int level);
};

class elliptics_storage_t:
    public api::storage_t
{
    public:
        typedef api::storage_t category_type;

    public:
        elliptics_storage_t(context_t& context,
                            const std::string& name,
                            const Json::Value& args);

        virtual
        std::string
        read(const std::string& collection,
             const std::string& key);

        virtual
        void
        write(const std::string& collection,
              const std::string& key,
              const std::string& blob);

        virtual
        std::vector<std::string>
        list(const std::string& collection);

        virtual
        void
        remove(const std::string& collection,
               const std::string& key);

    private:
        std::string id(const std::string& collection,
                       const std::string& key)
        {
            return collection + '\0' + key;
        };

    private:
        context_t& m_context;
        std::shared_ptr<logging::log_t> m_log;

        log_adapter_t m_log_adapter;
        ioremap::elliptics::node m_node;
        ioremap::elliptics::session m_session;

        std::vector<int> m_groups;
};

}}

#endif
