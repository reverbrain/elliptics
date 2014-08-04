/*
 * Copyright 2013+ Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef __CPP_SESSION_INDEXES_HPP
#define __CPP_SESSION_INDEXES_HPP

#include "elliptics/cppdef.h"

#include <msgpack.hpp>

#include <iostream>

#define DNET_INDEX_TABLE_MAGIC 0x5DA38CFBE7734027ull
#define DNET_INDEX_TABLE_MAGIC_SIZE 8

namespace ioremap { namespace elliptics {

enum {
	DNET_INDEXES_CAPPED_REMOVED = 1
};

struct dnet_index_entry : public index_entry
{
	dnet_index_entry()
	{
		time.tsec = 0;
		time.tnsec = 0;
	}

	dnet_index_entry(const dnet_raw_id &index, const data_pointer &data, const dnet_time &time)
		: index_entry(index, data), time(time)
	{}

	dnet_time time;
};

struct dnet_indexes
{
	int shard_id;
	int shard_count;
	std::vector<dnet_index_entry> indexes;
};


template <typename T>
static inline void indexes_unpack_raw(const data_pointer &file, T *data)
{
	static const unsigned long long magic = dnet_bswap64(DNET_INDEX_TABLE_MAGIC);

	if (file.size() < DNET_INDEX_TABLE_MAGIC_SIZE
		|| memcmp(file.data(), &magic, DNET_INDEX_TABLE_MAGIC_SIZE) != 0) {
		throw std::runtime_error("Invalid magic");
	}

	msgpack::unpacked msg;
	msgpack::unpack(&msg, file.data<char>() + DNET_INDEX_TABLE_MAGIC_SIZE, file.size() - DNET_INDEX_TABLE_MAGIC_SIZE);
	msg.get().convert(data);
}

template <typename T>
static inline void indexes_unpack(dnet_node *node, dnet_id *id, const data_pointer &file, T *data, const char *scope)
{
	try {
		indexes_unpack_raw(file, data);
	} catch (const std::exception &e) {
		DNET_DUMP_ID_LEN(id_str, id, DNET_ID_SIZE);
		dnet_log_raw(node, int(DNET_LOG_ERROR), "%s: %s: unpack exception: %s, file-size: %zu",
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
		dnet_log_raw(node, int(DNET_LOG_ERROR), "%s: %s: unpack exception: %s, file-size: %zu",
			id_str, scope, e.what(), file.size());
		data->clear();
	}
}

static inline dnet_raw_id transform_index_id(session &sess, const dnet_raw_id &data_id, int shard_id)
{
	dnet_raw_id id;
	dnet_indexes_transform_index_id(sess.get_native_node(), &data_id, &id, shard_id);
	return id;
}

}} /* namespace ioremap::elliptics */

namespace msgpack
{
using namespace ioremap::elliptics;

enum dnet_indexes_version : uint16_t {
	dnet_indexes_version_second = 2
};

enum find_indexes_result_entry_version : uint16_t {
	find_indexes_result_entry_version_first = 1
};

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

inline dnet_index_entry &operator >>(msgpack::object o, dnet_index_entry &v)
{
	if (o.type != msgpack::type::ARRAY || (o.via.array.size != 2 && o.via.array.size != 4))
		throw msgpack::type_error();
	object *p = o.via.array.ptr;
	p[0].convert(&v.index);
	p[1].convert(&v.data);
	if (o.via.array.size != 2) {
		p[2].convert(&v.time.tsec);
		p[3].convert(&v.time.tnsec);
	} else {
		v.time.tsec = 0;
		v.time.tnsec = 0;
	}
	return v;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const dnet_index_entry &v)
{
	o.pack_array(4);
	o.pack(v.index);
	o.pack(v.data);
	o.pack(v.time.tsec);
	o.pack(v.time.tnsec);
	return o;
}

inline dnet_indexes &operator >>(msgpack::object o, dnet_indexes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 1)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case dnet_indexes_version_second: {
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
	o.pack(uint16_t(dnet_indexes_version_second));
	o.pack(v.indexes);
	o.pack(v.shard_id);
	o.pack(v.shard_count);
	return o;
}

template <typename Stream>
inline msgpack::packer<Stream> &operator <<(msgpack::packer<Stream> &o, const find_indexes_result_entry &result)
{
	o.pack_array(3);
	o.pack(uint16_t(find_indexes_result_entry_version_first));
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
	case find_indexes_result_entry_version_first: {
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
