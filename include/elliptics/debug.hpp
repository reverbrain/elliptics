/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef ELLIPTICS_DEBUG_HPP
#define ELLIPTICS_DEBUG_HPP

#include <time.h>

#include <iostream>
#include <map>

#include "elliptics/interface.h"
#include "elliptics/packet.h"
#include "elliptics/result_entry.hpp"

inline std::ostream &operator <<(std::ostream &out, const dnet_raw_id &v)
{
	out << dnet_dump_id_str(v.id);
	return out;
}

inline std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::index_entry &v)
{
	out << "(id: " << v.index << ", data-size: " << v.data.size() << ")";
	return out;
}

inline std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::data_pointer &v)
{
	out << v.to_string();
	return out;
}

template <typename T>
inline std::ostream &operator <<(std::ostream &out, const std::vector<T> &v)
{
	out << "v{";
	for (size_t i = 0; i < v.size(); ++i) {
		if (i)
			out << ",";
		out << v[i];
	}
	out << "}";
	return out;
}

template <typename K, typename V>
inline std::ostream &operator <<(std::ostream &out, const std::map<K, V> &v)
{
	out << "m{";
	for (auto it = v.begin(); it != v.end(); ++it) {
		if (it != v.begin())
			out << ",";
		out << *it;
	}
	out << "}";
	return out;
}

template <typename K, typename V>
inline std::ostream &operator <<(std::ostream &out, const std::pair<K, V> &v)
{
	out << "p{" << v.first << "," << v.second << "}";
	return out;
}

inline std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::find_indexes_result_entry &v)
{
	out << "re{" << v.id << "," << v.indexes << "}";
	return out;
}

inline std::ostream &operator <<(std::ostream &out, const dnet_time &tv)
{
	char str[64];
	struct tm tm;

	localtime_r((time_t *)&tv.tsec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	out << str << "." << tv.tnsec / 1000;
	return out;
}

#endif // ELLIPTICS_DEBUG_HPP
