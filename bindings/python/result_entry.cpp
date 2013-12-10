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
#include "elliptics_io_attr.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_id index_entry_get_index(index_entry &result)
{
	return elliptics_id(result.index);
}

void index_entry_set_index(index_entry &result, const elliptics_id &id)
{
	result.index = id.raw_id();
}

std::string index_entry_get_data(index_entry &result)
{
	return result.data.to_string();
}

void index_entry_set_data(index_entry &result, const std::string& data)
{
	result.data = data_pointer::copy(data);
}

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

elliptics_io_attr read_result_get_io(read_result_entry &result) {
	return elliptics_io_attr(*result.io_attribute());
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

	bp::class_<index_entry>("IndexEntry")
		.add_property("index",
		              index_entry_get_index,
		              index_entry_set_index,
		              "index as elliptics.Id")
		.add_property("data",
		              index_entry_get_data,
		              index_entry_set_data,
		              "data associated with the index")
	;

	bp::class_<iterator_result_entry>("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id,
		              "Iterator integer ID. Which can be used for pausing, continuing and cancelling iterator")
		.add_property("status", &iterator_result_entry::status,
		              "Status of iterated key")
		.add_property("response", iterator_result_response,
		              "elliptics.IteratorResultResponse which provides meta information about iterated key")
		.add_property("response_data", iterator_result_response_data,
		              "Data of iterated key. May be empty if elliptics.iterator_flags.data hasn't been specified for iteration.")
		.add_property("address", result_entry_address<iterator_result_entry>,
		              "Address of node")
		.add_property("group_id", result_entry_group_id<iterator_result_entry>)
		.add_property("error", result_entry_error<iterator_result_entry>)
	;

	bp::class_<dnet_iterator_response>("IteratorResultResponse",
			bp::no_init)
		.add_property("key", iterator_response_get_key,
		              "elliptics.Id of iterated key")
		.add_property("timestamp", iterator_response_get_timestamp,
		              "elliptics.Time timestamp of iterated key")
		.add_property("user_flags", iterator_response_get_user_flags,
		              "Custom user-defined flags of iterated key")
		.add_property("size", iterator_response_get_size,
		              "Size of iterated key data")
	;

	bp::class_<read_result_entry>("ReadResultEntry")
		.add_property("data", read_result_get_data,
		              "Read data")
		.add_property("id", read_result_get_id,
		              "elliptics.Id of read object")
		.add_property("timestamp", read_result_get_timestamp,
		              "elliptics.Time timestamp of read object")
		.add_property("user_flags", read_result_get_user_flags,
		              "Custom user-defined flags of read object")
		.add_property("flags", read_result_get_flags,
		              "Internal flags of read object")
		.add_property("offset", read_result_get_offset,
		              "Offset with which object has been read")
		.add_property("size", read_result_get_size,
		              "Size of read object data")
		.add_property("address", result_entry_address<read_result_entry>,
		              "Node address which provides the object")
		.add_property("group_id", result_entry_group_id<read_result_entry>)
		.add_property("io_attribute", read_result_get_io,
		              "elliptics.IoAttr of read operation")
		.add_property("error", result_entry_error<read_result_entry>,
		              "elliptics.Error of operation execution")
	;

	bp::class_<lookup_result_entry>("LookupResultEntry")
		.add_property("storage_address", lookup_result_get_storage_address)
		.add_property("size", lookup_result_get_size,
		              "Size of data")
		.add_property("offset", lookup_result_get_offset,
		              "Offset of operation")
		.add_property("timestamp", lookup_result_get_timestamp,
		              "elliptics.Time timestamp of object")
		.add_property("checksum", lookup_result_get_checksum,
		              "elliptics.Id checksum of object")
		.add_property("filepath", lookup_result_get_filepath,
		              "path to object in the backend")
		.add_property("address", result_entry_address<lookup_result_entry>,
		              "Address of node where the object lives")
		.add_property("group_id", result_entry_group_id<lookup_result_entry>)
		.add_property("error", result_entry_error<lookup_result_entry>,
		              "elliptics.Error of operation execution")
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
		.add_property("id", find_indexes_result_get_id,
		              "elliptics.Id of id which has been found")
		.add_property("indexes", find_indexes_result_get_indexes,
		              "list of elliptics.IndexEntry which associated with the id")
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
		.add_property("la", dnet_stat_get_la, "Load average on the node")
		.add_property("bsize", &dnet_stat::bsize, "Block size")
		.add_property("frsize", &dnet_stat::frsize, "Fragment size")
		.add_property("blocks", &dnet_stat::blocks, "Filesystem size in frsize units")
		.add_property("bfree", &dnet_stat::bfree, "Free blocks")
		.add_property("bavail", &dnet_stat::bavail, "Free blocks for non-root")
		.add_property("files", &dnet_stat::files, "Inodes")
		.add_property("ffree", &dnet_stat::ffree, "Free inodes")
		.add_property("favail", &dnet_stat::favail, "Free inodes for non-root")
		.add_property("fsid", &dnet_stat::fsid, "File system ID")
		.add_property("flag", &dnet_stat::flag, "Mount flags")
		.add_property("vm_active", &dnet_stat::vm_active, "Virtual memory which is active")
		.add_property("vm_inactive", &dnet_stat::vm_inactive, "Virtual memory which is inactive")
		.add_property("vm_total", &dnet_stat::vm_total, "Total size of virtual memory")
		.add_property("vm_free", &dnet_stat::vm_free, "Size of free virtual memory")
		.add_property("vm_cached", &dnet_stat::vm_cached, "Virtual memory which is cached")
		.add_property("vm_buffers", &dnet_stat::vm_buffers, "Virtual memory which is buffered")
		.add_property("node_files", &dnet_stat::node_files, "Objects on the node")
		.add_property("node_files_removed", &dnet_stat::node_files_removed, "Objects on the node which marked as deleted")
		.def("__str__", dnet_stat_to_str)
		.def("__repr__", dnet_stat_to_repr)
	;

	bp::class_<stat_result_entry>("StatResultEntry")
		.add_property("statistics", stat_result_get_statistics,
		              "virtual memory and file system utilization statistics as elliptics.Statisitics")
		.add_property("address", result_entry_address<stat_result_entry>,
		              "elliptics.Address of the node which the statistics are belong")
		.add_property("group_id", result_entry_group_id<stat_result_entry>)
		.add_property("error", result_entry_error<stat_result_entry>,
		              "information about error")
	;

	bp::class_<address_statistics>("AddressStatistics", bp::no_init)
		.add_property("address", addr_stat_get_address,
		              "elliptics.Address of the client node from which the statistics was requested")
		.add_property("group_id", &address_statistics::group_id)
		.add_property("counters", addr_stat_get_counters,
		              "Python dict of operations counters statistics")
	;

	bp::class_<stat_count_result_entry>("StatCountResultEntry")
		.add_property("statistics", stat_count_result_get_statistics,
		              "Operations statistics as elliptics.AddressStatistics")
		.add_property("address", result_entry_address<stat_count_result_entry>,
		              "elliptics.Address of the node which the statistics are belonged")
		.add_property("group_id", result_entry_group_id<stat_count_result_entry>)
		.add_property("error", result_entry_error<stat_count_result_entry>,
		              "elliptics.Error information")
	;

}

} } } // namespace ioremap::elliptics::python
