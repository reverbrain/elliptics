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
#include <cocaine/api/service.hpp>
#include <cocaine/slot.hpp>

#include "elliptics/cppdef.h"

namespace cocaine {

class elliptics_service_t;

namespace storage {

class log_adapter_impl_t : public ioremap::elliptics::logger_interface
{
	public:
		log_adapter_impl_t(const std::shared_ptr<logging::log_t> &log);

		virtual void log(const int level, const char *msg);

	private:
		std::shared_ptr<logging::log_t> m_log;
};

class log_adapter_t : public ioremap::elliptics::logger
{
	public:
		log_adapter_t(const std::shared_ptr<logging::log_t> &log,
		const int level);
};

class elliptics_storage_t : public api::storage_t
{
	public:
		typedef api::storage_t category_type;
		typedef std::shared_ptr<logging::log_t> log_ptr;

		elliptics_storage_t(context_t &context,
			const std::string &name,
			const Json::Value &args);

		std::string read(const std::string &collection, const std::string &key);
		void write(const std::string &collection, const std::string &key, const std::string &blob, const std::vector<std::string> &tags);
		std::vector<std::string> find(const std::string &collection, const std::vector<std::string> &tags);
		void remove(const std::string &collection, const std::string &key);

	protected:
		ioremap::elliptics::async_read_result async_read(const std::string &collection, const std::string &key);
		ioremap::elliptics::async_write_result async_write(const std::string &collection, const std::string &key, const std::string &blob, const std::vector<std::string> &tags);
		ioremap::elliptics::async_find_indexes_result async_find(const std::string &collection, const std::vector<std::string> &tags);
		ioremap::elliptics::async_remove_result async_remove(const std::string &collection, const std::string &key);

		static std::vector<std::string> convert_list_result(const ioremap::elliptics::sync_find_indexes_result &result);

	private:
		std::string id(const std::string &collection,
		const std::string &key)
		{
			return collection + '\0' + key;
		}

	private:
		context_t &m_context;
		log_ptr m_log;

		log_adapter_t m_log_adapter;
		ioremap::elliptics::node m_node;
		ioremap::elliptics::session m_session;

		std::vector<int> m_groups;

		friend class cocaine::elliptics_service_t;
};

}}

#endif
