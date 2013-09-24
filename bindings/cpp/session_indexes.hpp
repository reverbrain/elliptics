#ifndef __CPP_SESSION_INDEXES_HPP
#define __CPP_SESSION_INDEXES_HPP

#include "elliptics/cppdef.h"

#include <msgpack.hpp>

#include <iostream>

#define DNET_INDEX_TABLE_MAGIC 0x5DA38CFBE7734027ull
#define DNET_INDEX_TABLE_MAGIC_SIZE 8

namespace ioremap { namespace elliptics {

struct dnet_indexes
{
	int shard_id;
	int shard_count;
	std::vector<index_entry> indexes;
};

struct raw_data_pointer
{
	const void *data;
	uint32_t size;

	bool operator ==(const raw_data_pointer &o) const
	{
		return size == o.size && (size == 0 || memcmp(data, o.data, size) == 0);
	}
};

struct raw_index_entry
{
	dnet_raw_id index;
	raw_data_pointer data;

	bool operator <(const raw_index_entry &o) const
	{
		return memcmp(index.id, o.index.id, sizeof(index.id)) < 0;
	}
};

struct raw_dnet_indexes
{
	int shard_id;
	int shard_count;
	std::vector<raw_index_entry> indexes;
};

struct update_request
{
	dnet_id id;
	std::vector<index_entry> indexes;
};

struct update_result_entry
{
	dnet_raw_id id;
	int error;
};

struct update_result
{
	std::vector<update_result_entry> indexes;
};

struct update_index_request
{
	dnet_id id;
	index_entry index;
	bool remove;
};

template <typename T>
static inline void indexes_unpack(dnet_node *node, dnet_id *id, const data_pointer &file, T *data, const char *scope)
{
	static const unsigned long long magic = dnet_bswap64(DNET_INDEX_TABLE_MAGIC);

	try {
		if (file.size() < DNET_INDEX_TABLE_MAGIC_SIZE
			|| memcmp(file.data(), &magic, DNET_INDEX_TABLE_MAGIC_SIZE) != 0) {
			throw std::runtime_error("Invalid magic");
		}

		msgpack::unpacked msg;
		msgpack::unpack(&msg, file.data<char>() + DNET_INDEX_TABLE_MAGIC_SIZE, file.size() - DNET_INDEX_TABLE_MAGIC_SIZE);
		msg.get().convert(data);
	} catch (const std::exception &e) {
		DNET_DUMP_ID_LEN(id_str, id, DNET_ID_SIZE);
		dnet_log_raw(node, DNET_LOG_ERROR, "%s: %s: unpack exception: %s, file-size: %zu\n",
			id_str, scope, e.what(), file.size());
		data->shard_id = 0;
		data->shard_count = 0;
		data->indexes.clear();
	}
}

static inline void find_result_unpack(dnet_node *node, dnet_id *id, const data_pointer &file, sync_find_indexes_result *data, const char *scope)
{
	try {
		msgpack::unpacked msg;
		msgpack::unpack(&msg, file.data<char>(), file.size());
		msg.get().convert(data);
	} catch (const std::exception &e) {
		DNET_DUMP_ID(id_str, id);
		dnet_log_raw(node, DNET_LOG_ERROR, "%s: %s: unpack exception: %s, file-size: %zu\n",
			id_str, scope, e.what(), file.size());
		data->clear();
	}
}

static inline dnet_raw_id transform_index_id(session &sess, const dnet_raw_id &data_id, int shard_id)
{
	dnet_raw_id id;
	dnet_indexes_transform_index_id(sess.get_node().get_native(), &data_id, &id, shard_id);
	return id;
}

}} /* namespace ioremap::elliptics */

namespace msgpack
{
using namespace ioremap::elliptics;

inline dnet_id &operator >>(msgpack::object o, dnet_id &v)
{
	if (o.type != msgpack::type::RAW || o.via.raw.size != sizeof(dnet_id))
		throw msgpack::type_error();
	memcpy(&v, o.via.raw.ptr, sizeof(dnet_id));
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_id &v)
{
	o.pack_raw(sizeof(dnet_id));
	o.pack_raw_body(reinterpret_cast<const char *>(&v), sizeof(v));
	return o;
}

inline dnet_raw_id &operator >>(msgpack::object o, dnet_raw_id &v)
{
	if (o.type != msgpack::type::RAW || o.via.raw.size != sizeof(v.id))
		throw msgpack::type_error();
	memcpy(v.id, o.via.raw.ptr, sizeof(v.id));
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_raw_id &v)
{
	o.pack_raw(sizeof(v.id));
	o.pack_raw_body(reinterpret_cast<const char *>(v.id), sizeof(v.id));
	return o;
}

inline data_pointer &operator >>(msgpack::object o, data_pointer &v)
{
	if (o.type != msgpack::type::RAW)
		throw msgpack::type_error();
	if (o.via.raw.size)
		v = data_pointer::copy(o.via.raw.ptr, o.via.raw.size);
	else
		v = data_pointer();
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const data_pointer &v)
{
	o.pack_raw(v.size());
	o.pack_raw_body(reinterpret_cast<char *>(v.data()), v.size());
	return o;
}

inline raw_data_pointer &operator >>(msgpack::object o, raw_data_pointer &v)
{
	if (o.type != msgpack::type::RAW)
		throw msgpack::type_error();
	if (o.via.raw.size) {
		v.data = o.via.raw.ptr;
		v.size = o.via.raw.size;
	} else {
		v.data = NULL;
		v.size = 0;
	}
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const raw_data_pointer &v)
{
	o.pack_raw(v.size);
	o.pack_raw_body(reinterpret_cast<const char *>(v.data), v.size);
	return o;
}

inline index_entry &operator >>(msgpack::object o, index_entry &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();
	object *p = o.via.array.ptr;
	p[0].convert(&v.index);
	p[1].convert(&v.data);
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const index_entry &v)
{
	o.pack_array(2);
	o.pack(v.index);
	o.pack(v.data);
	return o;
}

inline raw_index_entry &operator >>(msgpack::object o, raw_index_entry &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();
	object *p = o.via.array.ptr;
	p[0].convert(&v.index);
	p[1].convert(&v.data);
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const raw_index_entry &v)
{
	o.pack_array(2);
	o.pack(v.index);
	o.pack(v.data);
	return o;
}

inline update_result_entry &operator >>(msgpack::object o, update_result_entry &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size != 2)
		throw msgpack::type_error();
	object *p = o.via.array.ptr;
	p[0].convert(&v.id);
	p[1].convert(&v.error);
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const update_result_entry &v)
{
	o.pack_array(2);
	o.pack(v.id);
	o.pack(v.error);
	return o;
}

// Keep it in sync with raw_dnet_indexes
inline dnet_indexes &operator >>(msgpack::object o, dnet_indexes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 1)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 2: {
		if (size != 4)
			throw msgpack::type_error();

		p[1].convert(&v.indexes);
		p[2].convert(&v.shard_id);
		p[3].convert(&v.shard_count);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_indexes &v)
{
	o.pack_array(4);
	o.pack(2);
	o.pack(v.indexes);
	o.pack(v.shard_id);
	o.pack(v.shard_count);
	return o;
}

// Keep it in sync with dnet_indexes
inline raw_dnet_indexes &operator >>(msgpack::object o, raw_dnet_indexes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 1)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 2: {
		if (size != 4)
			throw msgpack::type_error();

		p[1].convert(&v.indexes);
		p[2].convert(&v.shard_id);
		p[3].convert(&v.shard_count);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const raw_dnet_indexes &v)
{
	o.pack_array(4);
	o.pack(2);
	o.pack(v.indexes);
	o.pack(v.shard_id);
	o.pack(v.shard_count);
	return o;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const update_request &request)
{
	o.pack_array(3);
	o.pack(1); // version
	o.pack(request.id);
	o.pack(request.indexes);
	return o;
}

inline update_request &operator >>(msgpack::object obj, update_request &request)
{
	if (obj.type != msgpack::type::ARRAY || obj.via.array.size < 1)
		throw msgpack::type_error();

	object *array = obj.via.array.ptr;
	const uint32_t size = obj.via.array.size;

	uint16_t version = 0;
	array[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 3)
			throw msgpack::type_error();

		array[1].convert(&request.id);
		array[2].convert(&request.indexes);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return request;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const update_index_request &request)
{
	o.pack_array(4);
	o.pack(1); // version
	o.pack(request.id);
	o.pack(request.index);
	o.pack(request.remove);
	return o;
}

inline update_index_request &operator >>(msgpack::object obj, update_index_request &request)
{
	if (obj.type != msgpack::type::ARRAY || obj.via.array.size < 1)
		throw msgpack::type_error();

	object *array = obj.via.array.ptr;
	const uint32_t size = obj.via.array.size;

	uint16_t version = 0;
	array[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 4)
			throw msgpack::type_error();

		array[1].convert(&request.id);
		array[2].convert(&request.index);
		array[3].convert(&request.remove);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return request;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const update_result &result)
{
	o.pack_array(2);
	o.pack(1); // version
	o.pack(result.indexes);
	return o;
}

inline update_result &operator >>(msgpack::object obj, update_result &result)
{
	if (obj.type != msgpack::type::ARRAY || obj.via.array.size < 1)
		throw msgpack::type_error();

	object *array = obj.via.array.ptr;
	const uint32_t size = obj.via.array.size;

	uint16_t version = 0;
	array[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 2)
			throw msgpack::type_error();

		array[1].convert(&result.indexes);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return result;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const find_indexes_result_entry &result)
{
	o.pack_array(3);
	o.pack(1); // version
	o.pack(result.id);
	o.pack(result.indexes);
	return o;
}

inline find_indexes_result_entry &operator >>(msgpack::object obj, find_indexes_result_entry &result)
{
	if (obj.type != msgpack::type::ARRAY || obj.via.array.size < 1)
		throw msgpack::type_error();

	object *array = obj.via.array.ptr;
	const uint32_t size = obj.via.array.size;

	uint16_t version = 0;
	array[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 3)
			throw msgpack::type_error();

		array[1].convert(&result.id);
		array[2].convert(&result.indexes);
		break;
	}
	default:
		throw msgpack::type_error();
	}

	return result;
}

} /* namespace msgpack */

#endif /* __CPP_SESSION_INDEXES_HPP */
