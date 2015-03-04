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
#include "py_converters.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_id index_entry_get_index(index_entry &result)
{
	return elliptics_id(result.index);
}

void index_entry_set_index(index_entry &result, const elliptics_id &id)
{
	memcpy(result.index.id, id.id().id, DNET_ID_SIZE);
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

uint64_t iterator_response_get_total_keys(dnet_iterator_response *response)
{
	return response->total_keys;
}

uint64_t iterator_response_get_iterated_keys(dnet_iterator_response *response)
{
	return response->iterated_keys;
}

int iterator_response_get_status(dnet_iterator_response *response)
{
	return response->status;
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

uint64_t read_result_get_total_size(read_result_entry &result) {
	return result.io_attribute()->total_size;
}

elliptics_io_attr read_result_get_io(read_result_entry &result) {
	return elliptics_io_attr(*result.io_attribute());
}

std::string lookup_result_get_storage_address(const lookup_result_entry &result)
{
	return std::string(dnet_addr_string(result.storage_address()));
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
	return dnet_addr_string(context.address());
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
	return convert_to_list(result.indexes);
}

bool callback_result_is_valid(callback_result_entry &result)
{
	return result.is_valid();
}

bool callback_result_is_ack(callback_result_entry &result)
{
	return result.is_ack();
}

bool callback_result_is_final(callback_result_entry &result)
{
	return result.is_final();
}

int callback_result_status(callback_result_entry &result)
{
	return result.status();
}

error callback_result_error(callback_result_entry &result)
{
	return error(result.error().code(), result.error().message());
}

std::string callback_result_data(callback_result_entry &result)
{
	return result.data().to_string();
}

std::string callback_entry_address(const callback_result_entry &result)
{
	return dnet_addr_string(result.address());
}

int callback_entry_group_id(const callback_result_entry &result)
{
	return result.command()->id.group_id;
}

int callback_entry_backend_id(const callback_result_entry &result) {
	return result.command()->backend_id;
}

uint64_t callback_entry_trace_id(const callback_result_entry &result) {
	return result.command()->trace_id;
}

uint64_t callback_entry_trans(const callback_result_entry &result) {
	return result.command()->trans;
}

uint64_t callback_result_size(callback_result_entry &result)
{
	return result.size();
}

std::string monitor_stat_result_get_statistics(monitor_stat_result_entry &result) {
	return result.statistics();
}

elliptics_id route_entry_get_id(const dnet_route_entry &entry) {
	return elliptics_id(entry.id, entry.group_id);
}

std::string route_entry_get_address(const dnet_route_entry &entry) {
	return std::string(dnet_addr_string(&entry.addr));
}

elliptics_time dnet_backend_status_get_last_start(const dnet_backend_status &result) {
	return elliptics_time(result.last_start);
}

bool dnet_backend_status_get_read_only(const dnet_backend_status &result) {
	return bool(result.read_only);
}

bp::list dnet_backend_status_result_get_backends(const backend_status_result_entry &result) {
	bp::list ret;

	for (size_t i = 0; i < result.count(); ++i) {
		ret.append(result.backend(i));
	}

	return ret;
}

void init_result_entry() {

	bp::class_<callback_result_entry>("CallbackResultEntry")
		.add_property("is_valid", callback_result_is_valid)
		.add_property("is_ack", callback_result_is_ack)
		.add_property("is_final", callback_result_is_final)
		.add_property("status", callback_result_status)
		.add_property("data", callback_result_data)
		.add_property("size", callback_result_size)
		.add_property("error", callback_result_error)
		.add_property("address", callback_entry_address)
		.add_property("group_id", callback_entry_group_id)
		.add_property("backend_id", callback_entry_backend_id)
		.add_property("trace_id", callback_entry_trace_id)
		.add_property("trans", callback_entry_trans)
	;

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

	bp::class_<iterator_result_entry, bp::bases<callback_result_entry> >("IteratorResultEntry")
		.add_property("id", &iterator_result_entry::id,
		              "Iterator integer ID. Which can be used for pausing, continuing and cancelling iterator")
		.add_property("response", iterator_result_response,
		              "elliptics.IteratorResultResponse which provides meta information about iterated key")
		.add_property("response_data", iterator_result_response_data,
		              "Data of iterated key. May be empty if elliptics.iterator_flags.data hasn't been specified for iteration.")
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
		.add_property("total_keys", iterator_response_get_total_keys,
		              "Number of all keys")
		.add_property("iterated_keys", iterator_response_get_iterated_keys,
		              "Number of iterated keys")
		.add_property("status", iterator_response_get_status,
		              "Status of iterated key:\n"
		              "0 - common key\n"
		              "1 - keepalive response")
	;

	bp::class_<read_result_entry, bp::bases<callback_result_entry> >("ReadResultEntry")
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
		.add_property("total_size", read_result_get_total_size,
		              "Total size of object data")
		.add_property("io_attribute", read_result_get_io,
		              "elliptics.IoAttr of read operation")
	;

	bp::class_<lookup_result_entry, bp::bases<callback_result_entry> >("LookupResultEntry")
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
	;

	bp::class_<exec_context>("ExecContext")
		.add_property("event", exec_context_get_event)
		.add_property("data", exec_context_get_data)
		.add_property("src_key", exec_context_get_src_key)
		.add_property("src_id", exec_context_get_src_id)
		.add_property("address", exec_context_get_address)
	;

	bp::class_<exec_result_entry, bp::bases<callback_result_entry> >("ExecResultEntry")
		.add_property("context", exec_result_get_context)
	;

	bp::class_<find_indexes_result_entry>("FindIndexesResultEntry")
		.add_property("id", find_indexes_result_get_id,
		              "elliptics.Id of id which has been found")
		.add_property("indexes", find_indexes_result_get_indexes,
		              "list of elliptics.IndexEntry which associated with the id")
	;

	bp::class_<monitor_stat_result_entry, bp::bases<callback_result_entry> >("MonitorStatResultEntry")
		.add_property("statistics", monitor_stat_result_get_statistics)
	;

	bp::class_<dnet_route_entry>("RouteEntry")
		.add_property("id", route_entry_get_id)
		.add_property("address", route_entry_get_address)
		.add_property("backend_id", &dnet_route_entry::backend_id)
	;

	bp::class_<backend_status_result_entry, bp::bases<callback_result_entry> >("BackendStatusResultEntry")
		.add_property("backends", &dnet_backend_status_result_get_backends)
	;

	bp::class_<dnet_backend_status>("BackendStatus")
		.add_property("backend_id", &dnet_backend_status::backend_id)
		.add_property("state", &dnet_backend_status::state)
		.add_property("defrag_state", &dnet_backend_status::defrag_state)
		.add_property("last_start", dnet_backend_status_get_last_start)
		.add_property("last_start_err", &dnet_backend_status::last_start_err)
		.add_property("read_only", dnet_backend_status_get_read_only)
	;

}

} } } // namespace ioremap::elliptics::python
