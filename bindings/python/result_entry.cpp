/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*/

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

uint64_t iterator_response_get_size(dnet_iterator_response *response)
{
	return response->size;
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

std::string exec_context_get_event(exec_context &context)
{
	return context.event();
}

std::string exec_context_get_data(exec_context &context)
{
	return context.data().to_string();
}

int exec_context_get_src_key(exec_context &context)
{
	return context.src_key();
}

elliptics_id exec_context_get_src_id(exec_context &context)
{
	const dnet_raw_id *raw = context.src_id();
	return elliptics_id(*raw);
}

std::string exec_context_get_address(exec_context &context)
{
	return dnet_server_convert_dnet_addr(context.address());
}

exec_context exec_result_get_context(exec_result_entry &result)
{
	return result.context();
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

bool callback_result_is_valid(callback_result_entry &result)
{
	return result.is_valid();
}

bool callback_result_is_ack(callback_result_entry &result)
{
	return result.is_ack();
}

int callback_result_status(callback_result_entry &result)
{
	return result.status();
}

template <typename T>
error result_entry_error(T &result)
{
	return error(result.error().code(), result.error().message());
}

std::string callback_result_data(callback_result_entry &result)
{
	return result.data().to_string();
}

template <typename T>
std::string result_entry_address(const T &result)
{
	return dnet_server_convert_dnet_addr(result.address());
}

template <typename T>
int result_entry_group_id(const T &result)
{
	return result.command()->id.group_id;
}

uint64_t callback_result_size(callback_result_entry &result)
{
	return result.size();
}

dnet_stat stat_result_get_statistics(stat_result_entry &result)
{
	return *(result.statistics());
}

struct address_statistics {
	address_statistics(const dnet_addr_stat *stat, int group_id)
	: stat(stat)
	, group_id(group_id)
	{}

	int num() { return stat->num; }
	int cmd_num() { return stat->cmd_num; }

	const dnet_addr_stat* stat;

	int group_id;
};

address_statistics stat_count_result_get_statistics(stat_count_result_entry &result)
{
	return address_statistics(result.statistics(), result.command()->id.group_id);
}

std::string addr_stat_get_address(address_statistics &stat) {
	return std::string(dnet_server_convert_dnet_addr(&stat.stat->addr));
}

bp::dict addr_stat_get_counters(address_statistics &stat) {
	bp::dict node_stat, storage_commands, proxy_commands, counters;
	auto as = stat.stat;

	for (int i = 0; i < as->num; ++i) {
		if (i < as->cmd_num) {
			storage_commands[std::string(dnet_counter_string(i, as->cmd_num))] =
			    bp::make_tuple((unsigned long long)as->count[i].count,
			                   (unsigned long long)as->count[i].err);
		} else if (i < (as->cmd_num * 2)) {
			proxy_commands[std::string(dnet_counter_string(i, as->cmd_num))] =
			    bp::make_tuple((unsigned long long)as->count[i].count,
			                   (unsigned long long)as->count[i].err);
		} else {
			counters[std::string(dnet_counter_string(i, as->cmd_num))] =
			    bp::make_tuple((unsigned long long)as->count[i].count,
			                   (unsigned long long)as->count[i].err);
		}
	}

	node_stat["storage_commands"] = storage_commands;
	node_stat["proxy_commands"] = proxy_commands;
	node_stat["counters"] = counters;

	return node_stat;
}

bp::list dnet_stat_get_la(const dnet_stat &stat)
{
	bp::list ret;
	for (uint8_t i = 0; i < 3; ++i) {
		ret.append(stat.la[i]);
	}
	return ret;
}

std::string dnet_stat_to_str(const dnet_stat &stat)
{
	char output[1024];

	float la[3];

	for (uint8_t i = 0; i < 3; ++i) {
		la[i] = (float)stat.la[i] / 100.0;
	}


	auto nchar = sprintf(output, "la: %3.2f %3.2f %3.2f\n"
	                     "mem: total: %8llu kB, free: %8llu kB, "
	                     "cache: %8llu kB, buffers: %8llu, "
	                     "active: %8llu, inactive: %8llu\n"
	                     "fs: total: %8llu mB, avail: %8llu/%8llu mB",
	                     la[0], la[1], la[2],
	                     (unsigned long long)stat.vm_total, (unsigned long long)stat.vm_free,
	                     (unsigned long long)stat.vm_cached, (unsigned long long)stat.vm_buffers,
	                     (unsigned long long)stat.vm_active, (unsigned long long)stat.vm_inactive,
	                     (unsigned long long)(stat.frsize * stat.blocks / 1024 / 1024),
	                     (unsigned long long)(stat.bavail * stat.bsize / 1024 / 1024),
	                     (unsigned long long)(stat.bfree * stat.bsize / 1024 / 1024));
	return std::string(output, nchar);
}

std::string dnet_stat_to_repr(const dnet_stat &stat)
{
	std::string ret = "< Statistics:\n";

	ret += dnet_stat_to_str(stat);
	ret += "\n>";

	return ret;
}

void init_result_entry() {

	bp::class_<iterator_result_entry>("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id)
		.add_property("status", &iterator_result_entry::status)
		.add_property("response", iterator_result_response)
		.add_property("response_data", iterator_result_response_data)
		.add_property("address", result_entry_address<iterator_result_entry>)
		.add_property("group_id", result_entry_group_id<iterator_result_entry>)
		.add_property("error", result_entry_error<iterator_result_entry>)
	;

	bp::class_<dnet_iterator_response>("IteratorResultResponse",
			bp::no_init)
		.add_property("key", iterator_response_get_key)
		.add_property("timestamp", iterator_response_get_timestamp)
		.add_property("user_flags", iterator_response_get_user_flags)
		.add_property("size", iterator_response_get_size)
	;

	bp::class_<read_result_entry>("ReadResultEntry")
		.add_property("data", read_result_get_data)
		.add_property("id", read_result_get_id)
		.add_property("timestamp", read_result_get_timestamp)
		.add_property("user_flags", read_result_get_user_flags)
		.add_property("flags", read_result_get_flags)
		.add_property("offset", read_result_get_offset)
		.add_property("size", read_result_get_size)
		.add_property("address", result_entry_address<read_result_entry>)
		.add_property("group_id", result_entry_group_id<read_result_entry>)
		.add_property("error", result_entry_error<read_result_entry>)
	;

	bp::class_<lookup_result_entry>("LookupResultEntry")
		.add_property("storage_address", lookup_result_get_storage_address)
		.add_property("size", lookup_result_get_size)
		.add_property("offset", lookup_result_get_offset)
		.add_property("timestamp", lookup_result_get_timestamp)
		.add_property("checksum", lookup_result_get_checksum)
		.add_property("filepath", lookup_result_get_filepath)
		.add_property("address", result_entry_address<lookup_result_entry>)
		.add_property("group_id", result_entry_group_id<lookup_result_entry>)
		.add_property("error", result_entry_error<lookup_result_entry>)
	;

	bp::class_<exec_context>("ExecContext")
		.add_property("event", exec_context_get_event)
		.add_property("data", exec_context_get_data)
		.add_property("src_key", exec_context_get_src_key)
		.add_property("src_id", exec_context_get_src_id)
		.add_property("address", exec_context_get_address)
	;

	bp::class_<exec_result_entry>("ExecResultEntry")
		.add_property("context", exec_result_get_context)
		.add_property("address", result_entry_address<exec_result_entry>)
		.add_property("group_id", result_entry_group_id<exec_result_entry>)
	;

	bp::class_<find_indexes_result_entry>("FindIndexesResultEntry")
		.add_property("id", find_indexes_result_get_id)
		.add_property("indexes", find_indexes_result_get_indexes)
	;

	bp::class_<callback_result_entry>("CallbackResultEntry")
		.add_property("is_valid", callback_result_is_valid)
		.add_property("is_ask", callback_result_is_ack)
		.add_property("status", callback_result_status)
		.add_property("data", callback_result_data)
		.add_property("size", callback_result_size)
		.add_property("error", result_entry_error<callback_result_entry>)
		.add_property("address", result_entry_address<callback_result_entry>)
		.add_property("group_id", result_entry_group_id<callback_result_entry>)
	;

	bp::class_<dnet_stat>("Statisitics", bp::no_init)
		.add_property("la", dnet_stat_get_la)
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
		.def("__str__", dnet_stat_to_str)
		.def("__repr__", dnet_stat_to_repr)
	;

	bp::class_<stat_result_entry>("StatResultEntry")
		.add_property("statistics", stat_result_get_statistics)
		.add_property("address", result_entry_address<stat_result_entry>)
		.add_property("group_id", result_entry_group_id<stat_result_entry>)
		.add_property("error", result_entry_error<stat_result_entry>)
	;

	bp::class_<address_statistics>("AddressStatistics", bp::no_init)
		.add_property("address", addr_stat_get_address)
		.add_property("group_id", &address_statistics::group_id)
		.add_property("counters", addr_stat_get_counters)
	;

	bp::class_<dnet_stat_count>("StatisticCounters")
		.add_property("counter", &dnet_stat_count::count)
		.add_property("errors", &dnet_stat_count::err)
	;

	bp::class_<stat_count_result_entry>("StatCountResultEntry")
		.add_property("statistics", stat_count_result_get_statistics)
		.add_property("address", result_entry_address<stat_count_result_entry>)
		.add_property("group_id", result_entry_group_id<stat_count_result_entry>)
		.add_property("error", result_entry_error<stat_count_result_entry>)
	;

}

} } } // namespace ioremap::elliptics::python
