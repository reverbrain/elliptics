#ifndef __ELLIPTICS_SESSION_INDEXES_HPP
#define __ELLIPTICS_SESSION_INDEXES_HPP

#include <msgpack.hpp>

#include "elliptics/cppdef.h"

static inline bool operator <(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) < 0;
}

static inline bool operator ==(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const dnet_raw_id &a, const ioremap::elliptics::index_entry &b)
{
	return memcmp(a.id, b.index.id, sizeof(a.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const dnet_raw_id &b)
{
	return memcmp(b.id, a.index.id, sizeof(b.id)) == 0;
}

static inline bool operator ==(const ioremap::elliptics::data_pointer &a, const ioremap::elliptics::data_pointer &b)
{
	return a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

static inline bool operator ==(const ioremap::elliptics::index_entry &a, const ioremap::elliptics::index_entry &b)
{
	return a.data.size() == b.data.size()
		&& memcmp(b.index.id, a.index.id, sizeof(b.index.id)) == 0
		&& memcmp(a.data.data(), b.data.data(), a.data.size()) == 0;
}

namespace ioremap { namespace elliptics {

enum { skip_data = 0, compare_data = 1 };

template <int CompareData = compare_data>
struct dnet_raw_id_less_than
{
	inline bool operator() (const dnet_raw_id &a, const dnet_raw_id &b) const
	{
		return memcmp(a.id, b.id, sizeof(a.id)) < 0;
	}
	inline bool operator() (const index_entry &a, const dnet_raw_id &b) const
	{
		return operator() (a.index, b);
	}
	inline bool operator() (const dnet_raw_id &a, const index_entry &b) const
	{
		return operator() (a, b.index);
	}
	inline bool operator() (const index_entry &a, const index_entry &b) const
	{
		ssize_t cmp = memcmp(a.index.id, b.index.id, sizeof(b.index.id));
		if (CompareData && cmp == 0) {
			cmp = a.data.size() - b.data.size();
			if (cmp == 0) {
				cmp = memcmp(a.data.data(), b.data.data(), a.data.size());
			}
		}
		return cmp < 0;
	}
	inline bool operator() (const index_entry &a, const find_indexes_result_entry &b) const
	{
		return operator() (a.index, b.id);
	}
	inline bool operator() (const find_indexes_result_entry &a, const index_entry &b) const
	{
		return operator() (a.id, b.index);
	}
};

struct dnet_indexes
{
	std::vector<index_entry> indexes;
	std::vector<dnet_raw_id> friends;
};

static inline void indexes_unpack(const data_pointer &file, dnet_indexes *data)
{
	msgpack::unpacked msg;
	msgpack::unpack(&msg, file.data<char>(), file.size());
	msg.get().convert(data);
}

}} /* namespace ioremap::elliptics */

namespace msgpack
{
using namespace ioremap::elliptics;

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

inline dnet_indexes &operator >>(msgpack::object o, dnet_indexes &v)
{
	if (o.type != msgpack::type::ARRAY || o.via.array.size < 1)
		throw msgpack::type_error();

	object *p = o.via.array.ptr;
	const uint32_t size = o.via.array.size;
	uint16_t version = 0;
	p[0].convert(&version);
	switch (version) {
	case 1: {
		if (size != 3)
			throw msgpack::type_error();

		p[1].convert(&v.indexes);
		p[2].convert(&v.friends);
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
	o.pack_array(3);
	o.pack(1);
	o.pack(v.indexes);
	o.pack(v.friends);
	return o;
}

} /* namespace msgpack */



std::ostream &operator <<(std::ostream &out, const dnet_raw_id &v)
{
	out << dnet_dump_id_str(v.id);
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::index_entry &v)
{
	out << "(" << v.index << ",\"" << v.data.to_string() << "\")";
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::data_pointer &v)
{
	out << v.to_string();
	return out;
}

template <typename T>
std::ostream &operator <<(std::ostream &out, const std::vector<T> &v)
{
	out << "{";
	for (size_t i = 0; i < v.size(); ++i) {
		if (i)
			out << ",";
		out << v[i];
	}
	out << "}";
	return out;
}

template <typename K, typename V>
std::ostream &operator <<(std::ostream &out, const std::map<K, V> &v)
{
	out << "{";
	for (auto it = v.begin(); it != v.end(); ++it) {
		if (it != v.begin())
			out << ",";
		out << *it;
	}
	out << "}";
	return out;
}

template <typename K, typename V>
std::ostream &operator <<(std::ostream &out, const std::pair<K, V> &v)
{
	out << "(" << v.first << "," << v.second << ")";
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::find_indexes_result_entry &v)
{
	out << "(" << v.id << "," << v.indexes << ")";
	return out;
}

#endif /* __ELLIPTICS_SESSION_INDEXES_HPP */
