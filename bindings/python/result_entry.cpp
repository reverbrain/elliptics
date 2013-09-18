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
	;

	bp::class_<lookup_result_entry>("LookupResultEntry")
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

	bp::class_<stat_count_result_entry>("StatCountResultEntry")
	;

}

} } } // namespace ioremap::elliptics::python
