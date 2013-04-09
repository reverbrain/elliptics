#ifndef __ELLIPTICS_SESSION_INDEXES_HPP
#define __ELLIPTICS_SESSION_INDEXES_HPP

#include <iostream>

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
