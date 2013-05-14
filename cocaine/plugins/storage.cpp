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
namespace ell = ioremap::elliptics;

log_adapter_impl_t::log_adapter_impl_t(const std::shared_ptr<logging::log_t> &log ): m_log(log)
{
}

void log_adapter_impl_t::log(const int level, const char *message)
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

log_adapter_t::log_adapter_t(const std::shared_ptr<logging::log_t> &log, const int level)
	: ell::logger(new log_adapter_impl_t(log), level)
{
}

elliptics_storage_t::elliptics_storage_t(context_t &context, const std::string &name, const Json::Value &args) :
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
			m_node.add_remote(it->c_str(), nodes[*it].asInt());
			have_remotes = true;
		} catch(const ell::error &) {
			// Do nothing. Yes. Really. We only care if no remote nodes were added at all.
		}
	}

	if (!have_remotes) {
		throw configuration_error_t("can not connect to any remote node");
	}

	Json::Value groups(args["groups"]);

	if (groups.empty() || !groups.isArray()) {
		throw configuration_error_t("no groups has been specified");
	}

	std::transform(groups.begin(), groups.end(), std::back_inserter(m_groups), std::mem_fn(&Json::Value::asInt));

	m_session.set_groups(m_groups);
	m_session.set_exceptions_policy(ell::session::no_exceptions);
}

std::string elliptics_storage_t::read(const std::string &collection, const std::string &key)
{
	auto result = async_read(collection, key);
	result.wait();

	if (result.error()) {
		throw storage_error_t(result.error().message());
	}

	return result.get_one().file().to_string();
}

void elliptics_storage_t::write(const std::string &collection,
	const std::string &key,
	const std::string &blob)
{
	auto result = async_write(collection, key, blob);
	result.wait();

	COCAINE_LOG_DEBUG(
		m_log,
		"write finised: %s",
		result.error().message()
	);

	if (result.error()) {
		throw storage_error_t(result.error().message());
	}
}

std::vector<std::string> elliptics_storage_t::list(const std::string &collection) {
	auto result = async_list(collection);
	result.wait();

	if (result.error()) {
		throw storage_error_t(result.error().message());
	}

	return convert_list_result(result.get());
}

void elliptics_storage_t::remove(const std::string &collection, const std::string &key)
{
	auto result = async_remove(collection, key);
	result.wait();

	if (result.error()) {
		throw storage_error_t(result.error().message());
	}
}

ell::async_read_result elliptics_storage_t::async_read(const std::string &collection, const std::string &key)
{
	using namespace std::placeholders;

	COCAINE_LOG_DEBUG(
		m_log,
		"reading the '%s' object, collection: '%s'",
		key,
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	return session.read_data(key, 0, 0);
}

static void on_adding_index_finished(const elliptics_storage_t::log_ptr &log,
	ell::async_result_handler<ell::write_result_entry> handler,
	const ell::error_info &err)
{
	if (err) {
		COCAINE_LOG_DEBUG(
			log,
			"index adding failed: %s",
			err.message()
		);
	} else {
		COCAINE_LOG_DEBUG(
			log,
			"index adding completed"
		);
	}
	handler.complete(err);
}

static void on_write_finished(const elliptics_storage_t::log_ptr &log,
	ell::async_result_handler<ell::write_result_entry> handler,
	ell::session session,
	const std::string &key,
	const ell::sync_write_result &result,
	const ell::error_info &err)
{
	using namespace std::placeholders;

	if (err) {
		COCAINE_LOG_DEBUG(
			log,
			"write failed: %s",
			err.message()
		);
		handler.complete(err);
		return;
	}
	COCAINE_LOG_DEBUG(
		log,
		"write partially completed"
	);

	for (auto it = result.begin(); it != result.end(); ++it) {
		handler.process(*it);
	}

	std::vector<std::string> index_names = {
		std::string("list:collection")
	};
	std::vector<ell::data_pointer> index_data = {
		ell::data_pointer::copy(key.c_str(), key.size())
	};
	session.update_indexes(key, index_names, index_data)
		.connect(std::bind(on_adding_index_finished, log, handler, _2));
}

ell::async_write_result elliptics_storage_t::async_write(const std::string &collection, const std::string &key, const std::string &blob)
{
	using namespace std::placeholders;

	COCAINE_LOG_DEBUG(
		m_log,
		"writing the '%s' object, collection: '%s'",
		key,
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	ell::async_write_result result(session);
	ell::async_result_handler<ell::write_result_entry> handler(result);

	session.set_filter(ioremap::elliptics::filters::all_with_ack);
	return session.write_data(key, blob, 0);
//		.connect(std::bind(on_write_finished, m_log, handler, session, key, _1, _2));

	return result;
}

ell::async_find_indexes_result elliptics_storage_t::async_list(const std::string &collection)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"listing collection: '%s'",
		collection
	);
	using namespace std::placeholders;

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	return session.find_indexes(std::vector<std::string>(1, "list:collection"));
}

static void on_removing_index_finished(ell::async_result_handler<ell::callback_result_entry> handler,
	ell::session session,
	const std::string &key,
	const ell::sync_update_indexes_result &,
	const ell::error_info &err)
{
	using namespace std::placeholders;

	if (err) {
		handler.complete(err);
		return;
	}

	session.remove(key).connect(handler);
}

ell::async_remove_result elliptics_storage_t::async_remove(const std::string &collection, const std::string &key)
{
	using namespace std::placeholders;

	COCAINE_LOG_DEBUG(
		m_log,
		"removing the '%s' object, collection: '%s'",
		key,
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	ell::async_remove_result result(session);
	ell::async_result_handler<ell::callback_result_entry> handler(result);

	session.update_indexes(key, std::vector<std::string>(), std::vector<ell::data_pointer>())
		.connect(std::bind(on_removing_index_finished, handler, session, key, _1, _2));

	return result;
}

std::vector<std::string> elliptics_storage_t::convert_list_result(const ioremap::elliptics::sync_find_indexes_result &result)
{
	std::vector<std::string> promise_result;

	for (auto it = result.begin(); it != result.end(); ++it) {
		for (auto jt = it->indexes.begin(); jt != it->indexes.end(); ++jt) {
			promise_result.push_back(jt->second.to_string());
		}
	}

	return promise_result;
}
