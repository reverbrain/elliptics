#ifndef COCAINE_ELLIPTICS_SERVICE_HPP
#define COCAINE_ELLIPTICS_SERVICE_HPP

#include <cocaine/api/storage.hpp>
#include <cocaine/api/service.hpp>
#include <cocaine/messages.hpp>
#include <cocaine/slot.hpp>
#include "storage.hpp"

namespace cocaine {

struct elliptics_tag;

namespace elliptics {

struct cache_read
{
	typedef elliptics_tag tag;

	typedef boost::mpl::list<
	/* Key namespace. Currently no ACL checks are performed, so in theory any app can read
	   any other app data without restrictions. */
		std::string,
	/* Key. */
		std::string
	> tuple_type;

	typedef
	/* The stored value. Typically it will be serialized with msgpack, but it's not a strict
	   requirement. But as there's no way to know the format, try to unpack it anyway. */
		std::string
	result_type;
};

struct cache_write
{
	typedef elliptics_tag tag;

	typedef boost::mpl::list<
	/* Key namespace. */
		std::string,
	/* Key. */
		std::string,
	/* Value. Typically, it should be serialized with msgpack, so that the future reader could
	   assume that it can be deserialized safely. */
		std::string,
	/* Timeout. Life-time of the data, if not set it's unlimited */
		io::optional_with_default<int, 0>
	> tuple_type;
};

struct bulk_read {
	typedef elliptics_tag tag;

	typedef boost::mpl::list<
	/* Key namespace. Currently no ACL checks are performed, so in theory any app can read
	   any other app data without restrictions. */
		std::string,
	/* Keys. */
		std::vector<std::string>
	> tuple_type;

	typedef
	/* The stored values. Typically it will be serialized with msgpack, but it's not a strict
	   requirement. But as there's no way to know the format, try to unpack it anyway. */
		std::map<std::string, std::string>
	result_type;
};

struct bulk_write {
	typedef elliptics_tag tag;

	typedef boost::mpl::list<
	/* Key namespace. */
		std::string,
	/* Keys. */
		std::vector<std::string>,
	/* Values. Typically, it should be serialized with msgpack, so that the future reader could
	   assume that it can be deserialized safely. */
		std::vector<std::string>
	> tuple_type;

	typedef
	/* Write results. If write for some key fails errno can be accessed by the key. */
		std::map<std::string, int>
	result_type;
};
} // namespace cocaine::elliptics

namespace io {
template<>
struct protocol<elliptics_tag> : public protocol<storage_tag>
{
	typedef boost::mpl::int_<
		1
	>::type version;

	typedef boost::mpl::list<
		elliptics::cache_read,
		elliptics::cache_write,
		elliptics::bulk_read
//		elliptics::bulk_write
	> type;
};
} // namespace cocaine::io

class elliptics_service_t : public api::service_t
{
	public:
		elliptics_service_t(context_t &context,
			io::reactor_t &reactor,
			const std::string &name,
			const Json::Value &args);

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
};

} // namespace cocaine

#endif // COCAINE_ELLIPTICS_SERVICE_HPP
