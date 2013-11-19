#ifndef COCAINE_ELLIPTICS_SERVICE_HPP
#define COCAINE_ELLIPTICS_SERVICE_HPP

#include <cocaine/api/service.hpp>
#include <cocaine/dispatch.hpp>

#include "storage.hpp"

#include "cocaine/idl/elliptics.hpp"

namespace cocaine {

class elliptics_service_t : public api::service_t, public implements<io::elliptics_tag>
{
	public:
		elliptics_service_t(context_t &context,
			io::reactor_t &reactor,
			const std::string &name,
			const dynamic_t &args);

		virtual dispatch_t& prototype() { return *this; }

		deferred<std::string> read(const std::string &collection, const std::string &key);
		deferred<void> write(const std::string &collection, const std::string &key, const std::string &blob, const std::vector<std::string> &tags);
		deferred<std::vector<std::string> > find(const std::string &collection, const std::vector<std::string> &tags);
		deferred<void> remove(const std::string &collection, const std::string &key);
		deferred<std::string> cache_read(const std::string &collection, const std::string &key);
		deferred<void> cache_write(const std::string &collection, const std::string &key,
			const std::string &blob, int timeout);
		deferred<std::map<std::string, std::string> > bulk_read(const std::string &collection, const std::vector<std::string> &keys);
		deferred<std::map<std::string, int> > bulk_write(const std::string &collection, const std::vector<std::string> &keys,
			const std::vector<std::string> &blob);

	private:
		typedef storage::elliptics_storage_t::key_name_map key_name_map;

		static void on_read_completed(deferred<std::string> promise,
			const ioremap::elliptics::sync_read_result &result,
			const ioremap::elliptics::error_info &error);
		static void on_write_completed(deferred<void> promise,
			const ioremap::elliptics::sync_write_result &result,
			const ioremap::elliptics::error_info &error);
		static void on_find_completed(deferred<std::vector<std::string> > promise,
			const ioremap::elliptics::sync_find_indexes_result &result,
			const ioremap::elliptics::error_info &error);
		static void on_remove_completed(deferred<void> promise,
			const ioremap::elliptics::sync_remove_result &result,
			const ioremap::elliptics::error_info &error);
		static void on_bulk_read_completed(deferred<std::map<std::string, std::string> > promise,
			const key_name_map &keys,
			const ioremap::elliptics::sync_read_result &result,
			const ioremap::elliptics::error_info &error);
		static void on_bulk_write_completed(deferred<std::map<std::string, int> > promise,
			const key_name_map &keys,
			const ioremap::elliptics::sync_write_result &result,
			const ioremap::elliptics::error_info &error);

		// NOTE: This will keep the underlying storage active, as opposed to the usual usecase when
		// the storage object is destroyed after the node service finishes its initialization.
		api::category_traits<api::storage_t>::ptr_type m_storage;
		storage::elliptics_storage_t *m_elliptics;
		const std::unique_ptr<logging::log_t> m_log;
};

} // namespace cocaine

#endif // COCAINE_ELLIPTICS_SERVICE_HPP
