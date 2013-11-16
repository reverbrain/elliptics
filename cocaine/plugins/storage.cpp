/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
 * Copyright 2011-2012 Andrey Sibiryov <me@kobology.ru>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
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

namespace {

dnet_config parse_json_config(const Json::Value& args) {
	dnet_config cfg;

	std::memset(&cfg, 0, sizeof(cfg));

	cfg.wait_timeout   = args.get("wait-timeout", 5).asInt();
	cfg.check_timeout  = args.get("check-timeout", 20).asInt();
	cfg.io_thread_num  = args.get("io-thread-num", 0).asUInt();
	cfg.net_thread_num = args.get("net-thread-num", 0).asUInt();
	cfg.flags          = args.get("flags", 0).asInt();

	return cfg;
}

}

elliptics_storage_t::elliptics_storage_t(context_t &context, const std::string &name, const Json::Value &args) :
	category_type(context, name, args),
	m_context(context),
	m_log(new log_t(context, name)),
	m_log_adapter(m_log, args.get("verbosity", DNET_LOG_ERROR).asUInt()),
	m_config(parse_json_config(args)),
	m_node(m_log_adapter, m_config),
	m_session(m_node)
{
	Json::Value nodes(args["nodes"]);

	if(nodes.empty() || !nodes.isObject()) {
		throw storage_error_t("no nodes has been specified");
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
		throw storage_error_t("can not connect to any remote node");
	}

	Json::Value groups(args["groups"]);

	if (groups.empty() || !groups.isArray()) {
		throw storage_error_t("no groups has been specified");
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
	const std::string &blob,
	const std::vector<std::string> &tags)
{
	auto result = async_write(collection, key, blob, tags);
	result.wait();

	COCAINE_LOG_DEBUG(
		m_log,
		"write finished: %s",
		result.error().message()
	);

	if (result.error()) {
		throw storage_error_t(result.error().message());
	}
}

std::vector<std::string> elliptics_storage_t::find(const std::string &collection, const std::vector<std::string> &tags)
{
	auto result = async_find(collection, tags);
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
	const std::vector<std::string> &index_names,
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

	std::vector<ell::data_pointer> index_data(index_names.size(),
		ell::data_pointer::copy(key.c_str(), key.size()));

	session.set_indexes(key, index_names, index_data)
		.connect(std::bind(on_adding_index_finished, log, handler, _2));
}

ell::async_write_result elliptics_storage_t::async_write(const std::string &collection, const std::string &key, const std::string &blob, const std::vector<std::string> &tags)
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
	session.set_filter(ioremap::elliptics::filters::all_with_ack);

	auto write_result = session.write_data(key, blob, 0);

	if (tags.empty()) {
		return write_result;
	}

	ell::async_write_result result(session);
	ell::async_result_handler<ell::write_result_entry> handler(result);

	write_result.connect(std::bind(on_write_finished, m_log, handler, session, key, tags, _1, _2));

	return result;
}

ell::async_find_indexes_result elliptics_storage_t::async_find(const std::string &collection, const std::vector<std::string> &tags)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"listing collection: '%s'",
		collection
	);
	using namespace std::placeholders;

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	return session.find_all_indexes(tags);
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

	session.set_checker(ell::checkers::no_check);
	session.set_filter(ell::filters::all_with_ack);

	session.set_indexes(key, std::vector<std::string>(), std::vector<ell::data_pointer>())
		.connect(std::bind(on_removing_index_finished, handler, session, key, _1, _2));

	return result;
}

ioremap::elliptics::async_read_result elliptics_storage_t::async_cache_read(const std::string &collection, const std::string &key)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"cache reading the '%s' object, collection: '%s'",
		key,
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());
	session.set_ioflags(DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY);

	return session.read_data(key, 0, 0);
}

ioremap::elliptics::async_write_result elliptics_storage_t::async_cache_write(const std::string &collection, const std::string &key,
	const std::string &blob, int timeout)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"cache writing the '%s' object, collection: '%s'",
		key,
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());
	session.set_ioflags(DNET_IO_FLAGS_CACHE | DNET_IO_FLAGS_CACHE_ONLY);

	return session.write_cache(key, blob, timeout);
}

std::pair<ioremap::elliptics::async_read_result, elliptics_storage_t::key_name_map> elliptics_storage_t::async_bulk_read(
	const std::string &collection, const std::vector<std::string> &keys)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"bulk reading, collection: '%s'",
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());

	key_name_map keys_map;
	dnet_raw_id id;

	for (size_t i = 0; i < keys.size(); ++i) {
		session.transform(keys[i], id);
		keys_map[id] = keys[i];
	}

	return std::make_pair(session.bulk_read(keys), std::move(keys_map));
}

ioremap::elliptics::async_write_result elliptics_storage_t::async_bulk_write(const std::string &collection, const std::vector<std::string> &keys,
	const std::vector<std::string> &blobs)
{
	COCAINE_LOG_DEBUG(
		m_log,
		"bulk writing, collection: '%s'",
		collection
	);

	ell::session session = m_session.clone();
	session.set_namespace(collection.data(), collection.size());
	session.set_filter(ell::filters::all);

	std::vector<dnet_io_attr> ios;
	ios.reserve(blobs.size());

	dnet_io_attr io;
	dnet_id id;
	memset(&io, 0, sizeof(io));
	dnet_empty_time(&io.timestamp);
	memset(&id, 0, sizeof(id));

	for (size_t i = 0; i < blobs.size(); ++i) {
		session.transform(keys[i], id);
		memcpy(io.id, id.id, sizeof(io.id));

		io.size = blobs[i].size();

		ios.push_back(io);
	}

	return session.bulk_write(ios, blobs);
}

std::vector<std::string> elliptics_storage_t::convert_list_result(const ioremap::elliptics::sync_find_indexes_result &result)
{
	std::vector<std::string> promise_result;

	for (auto it = result.begin(); it != result.end(); ++it) {
		if (!it->indexes.empty()) {
			promise_result.push_back(it->indexes.front().data.to_string());
		}
	}

	return promise_result;
}
