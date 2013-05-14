#include "service.hpp"
#include <cocaine/messages.hpp>

#define debug() std::cerr << __PRETTY_FUNCTION__ << ": " << __LINE__ << " "

namespace cocaine {

using namespace std::placeholders;

elliptics_service_t::elliptics_service_t(context_t &context, io::reactor_t &reactor, const std::string &name, const Json::Value &args) :
	api::service_t(context, reactor, name, args),
	m_storage(api::storage(context, args.get("source", "core").asString())),
	m_elliptics(dynamic_cast<storage::elliptics_storage_t*>(m_storage.get()))
{
	debug() << m_elliptics << std::endl;

	if (!m_elliptics) {
		throw configuration_error_t("To use elliptics service storage must be also ellitips");
	}

	on<io::storage::read  >("read",   std::bind(&elliptics_service_t::read,   this, _1, _2));
	on<io::storage::write >("write",  std::bind(&elliptics_service_t::write,  this, _1, _2, _3));
	on<io::storage::remove>("remove", std::bind(&elliptics_service_t::remove, this, _1, _2));
	on<io::storage::list  >("list",   std::bind(&elliptics_service_t::list,   this, _1));
}

deferred<std::string> elliptics_service_t::read(const std::string &collection, const std::string &key)
{
	debug() << "read, collection: " << collection << ", key: " << key << std::endl;
	deferred<std::string> promise;

	m_elliptics->async_read(collection, key).connect(std::bind(&elliptics_service_t::on_read_completed,
		promise, _1, _2));

	return promise;
}

deferred<void> elliptics_service_t::write(const std::string &collection, const std::string &key, const std::string &blob)
{
	debug() << "write, collection: " << collection << ", key: " << key << std::endl;
	deferred<void> promise;

	m_elliptics->async_write(collection, key, blob).connect(std::bind(&elliptics_service_t::on_write_completed,
		promise, _1, _2));

	return promise;
}

deferred<std::vector<std::string> > elliptics_service_t::list(const std::string &collection)
{
	debug() << "lits, collection: " << collection << std::endl;
	deferred<std::vector<std::string> > promise;

	m_elliptics->async_list(collection).connect(std::bind(&elliptics_service_t::on_list_completed,
		promise, _1, _2));

	return promise;
}

deferred<void> elliptics_service_t::remove(const std::string &collection, const std::string &key)
{
	debug() << "remove, collection: " << collection << ", key: " << key << std::endl;
	deferred<void> promise;

	m_elliptics->async_remove(collection, key).connect(std::bind(&elliptics_service_t::on_remove_completed,
		promise, _1, _2));

	return promise;
}

void elliptics_service_t::on_read_completed(deferred<std::string> promise,
	const ioremap::elliptics::sync_read_result &result,
	const ioremap::elliptics::error_info &error)
{
	if (error) {
		promise.abort(cocaine::invocation_error, error.message());
	} else {
		promise.write(result[0].file().to_string());
	}
}

void elliptics_service_t::on_write_completed(deferred<void> promise,
	const ioremap::elliptics::sync_write_result &,
	const ioremap::elliptics::error_info &error)
{
	if (error) {
		promise.abort(cocaine::invocation_error, error.message());
	} else {
		promise.close();
	}
}

void elliptics_service_t::on_list_completed(deferred<std::vector<std::string> > promise,
	const ioremap::elliptics::sync_find_indexes_result &result,
	const ioremap::elliptics::error_info &error)
{
	if (error) {
		promise.abort(cocaine::invocation_error, error.message());
	} else {
		promise.write(storage::elliptics_storage_t::convert_list_result(result));
	}
}

void elliptics_service_t::on_remove_completed(deferred<void> promise,
	const ioremap::elliptics::sync_remove_result &,
	const ioremap::elliptics::error_info &error)
{
	if (error) {
		promise.abort(cocaine::invocation_error, error.message());
	} else {
		promise.close();
	}
}

}
