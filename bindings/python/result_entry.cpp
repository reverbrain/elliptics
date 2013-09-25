#include "result_entry.h"

#include <boost/python.hpp>
#include <boost/python/list.hpp>

#include <elliptics/result_entry.hpp>
#include <elliptics/interface.h>

#include "elliptics_id.h"
#include "elliptics_time.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

dnet_iterator_response iterator_result_response(iterator_result_entry result)
{
	return *result.reply();
}

std::string iterator_result_response_data(iterator_result_entry result)
{
	return result.reply_data().to_string();
}

elliptics_id iterator_response_get_key(dnet_iterator_response *response)
{
	return elliptics_id(response->key);
}

elliptics_time iterator_response_get_timestamp(dnet_iterator_response *response)
{
	return elliptics_time(response->timestamp);
}

uint64_t iterator_response_get_user_flags(dnet_iterator_response *response)
{
	return response->user_flags;
}

std::string read_result_get_data(read_result_entry &result)
{
	return result.file().to_string();
}

elliptics_id read_result_get_id(read_result_entry &result)
{
	dnet_raw_id id;
	memcpy(id.id, result.io_attribute()->id, sizeof(id.id));
	return elliptics_id(id);
}

elliptics_time read_result_get_timestamp(read_result_entry &result)
{
	return elliptics_time(result.io_attribute()->timestamp);
}

uint64_t read_result_get_user_flags(read_result_entry &result)
{
	return result.io_attribute()->user_flags;
}

uint32_t read_result_get_flags(read_result_entry &result)
{
	return result.io_attribute()->flags;
}

uint64_t read_result_get_offset(read_result_entry &result)
{
	return result.io_attribute()->offset;
}

uint64_t read_result_get_size(read_result_entry &result)
{
	return result.io_attribute()->size;
}

std::string lookup_result_get_storage_address(const lookup_result_entry &result)
{
	return std::string(dnet_server_convert_dnet_addr(result.storage_address()));
}

uint64_t lookup_result_get_size(const lookup_result_entry &result)
{
	return result.file_info()->size;
}

uint64_t lookup_result_get_offset(const lookup_result_entry &result)
{
	return result.file_info()->offset;
}

elliptics_time lookup_result_get_timestamp(const lookup_result_entry &result)
{
	return elliptics_time(result.file_info()->mtime);
}

elliptics_id lookup_result_get_checksum(const lookup_result_entry &result)
{
	dnet_raw_id id;
	memcpy(id.id, result.file_info()->checksum, DNET_CSUM_SIZE);
	return elliptics_id(id);
}

std::string lookup_result_get_filepath(const lookup_result_entry &result)
{
	return std::string(result.file_path());
}

std::string exec_result_get_event(exec_result_entry &result)
{
	return result.context().event();
}

std::string exec_result_get_data(exec_result_entry &result)
{
	return result.context().data().to_string();
}

int exec_result_get_src_key(exec_result_entry &result)
{
	return result.context().src_key();
}

elliptics_id exec_result_get_src_id(exec_result_entry &result)
{
	const dnet_raw_id *raw = result.context().src_id();
	return elliptics_id(*raw);
}

std::string exec_result_get_address(exec_result_entry &result)
{
	struct dnet_addr *addr = result.context().address();
	return dnet_server_convert_dnet_addr(addr);
}

elliptics_id find_indexes_result_get_id(find_indexes_result_entry &result)
{
	return elliptics_id(result.id);
}

bp::list find_indexes_result_get_indexes(find_indexes_result_entry &result)
{
	bp::list ret;

	for (auto it = result.indexes.begin(), end = result.indexes.end(); it != end; ++it) {
		ret.append(*it);
	}

	return ret;
}

dnet_stat stat_result_get_statistics(stat_result_entry &result)
{
	return *(result.statistics());
}

dnet_addr_stat stat_count_result_get_statistics(stat_count_result_entry &result)
{
	return *(result.statistics());
}

std::string addr_stat_get_address(dnet_addr_stat &stat)
{
	return std::string(dnet_server_convert_dnet_addr(&stat.addr));
}

void init_result_entry() {

	bp::class_<iterator_result_entry>("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id)
		.add_property("status", &iterator_result_entry::status)
		.add_property("response", iterator_result_response)
		.add_property("response_data", iterator_result_response_data)
	;

	bp::class_<dnet_iterator_response>("IteratorResultResponse",
			bp::no_init)
		.add_property("key", iterator_response_get_key)
		.add_property("timestamp", iterator_response_get_timestamp)
		.add_property("user_flags", iterator_response_get_user_flags)
	;

	bp::class_<read_result_entry>("ReadResultEntry")
		.add_property("data", read_result_get_data)
		.add_property("id", read_result_get_id)
		.add_property("timestamp", read_result_get_timestamp)
		.add_property("user_flags", read_result_get_user_flags)
		.add_property("flags", read_result_get_flags)
		.add_property("offset", read_result_get_offset)
		.add_property("size", read_result_get_size)
	;

	bp::class_<lookup_result_entry>("LookupResultEntry")
		.add_property("storage_address", lookup_result_get_storage_address)
		.add_property("size", lookup_result_get_size)
		.add_property("offset", lookup_result_get_offset)
		.add_property("timestamp", lookup_result_get_timestamp)
		.add_property("checksum", lookup_result_get_checksum)
		.add_property("filepath", lookup_result_get_filepath)
	;

	bp::class_<exec_result_entry>("ExecResultEntry")
		.add_property("event", exec_result_get_event)
		.add_property("data", exec_result_get_data)
		.add_property("src_key", exec_result_get_src_key)
		.add_property("src_id", exec_result_get_src_id)
		.add_property("address", exec_result_get_address)
	;

	bp::class_<find_indexes_result_entry>("FindIndexesResultEntry")
		.add_property("id", find_indexes_result_get_id)
		.add_property("indexes", find_indexes_result_get_indexes)
	;

	bp::class_<callback_result_entry>("CallbackResultEntry")
	;

	bp::class_<dnet_stat>("Statisitics", bp::no_init)
		.add_property("bsize", &dnet_stat::bsize)
		.add_property("frsize", &dnet_stat::frsize)
		.add_property("blocks", &dnet_stat::blocks)
		.add_property("bfree", &dnet_stat::bfree)
		.add_property("bavail", &dnet_stat::bavail)
		.add_property("files", &dnet_stat::files)
		.add_property("ffree", &dnet_stat::ffree)
		.add_property("favail", &dnet_stat::favail)
		.add_property("fsid", &dnet_stat::fsid)
		.add_property("flag", &dnet_stat::flag)
		.add_property("vm_active", &dnet_stat::vm_active)
		.add_property("vm_inactive", &dnet_stat::vm_inactive)
		.add_property("vm_total", &dnet_stat::vm_total)
		.add_property("vm_free", &dnet_stat::vm_free)
		.add_property("vm_cached", &dnet_stat::vm_cached)
		.add_property("vm_buffers", &dnet_stat::vm_buffers)
	;

	bp::class_<stat_result_entry>("StatResultEntry")
		.add_property("statistics", stat_result_get_statistics)
	;

	bp::class_<dnet_addr_stat>("AddressStatistics", bp::no_init)
		.add_property("address", addr_stat_get_address)
		.add_property("num", &dnet_addr_stat::num)
		.add_property("cmd_num", &dnet_addr_stat::cmd_num)
	;

	bp::class_<stat_count_result_entry>("StatCountResultEntry")
		.add_property("statistics", stat_count_result_get_statistics)
	;

}

} } } // namespace ioremap::elliptics::python
