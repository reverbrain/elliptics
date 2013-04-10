#ifndef __ELLIPTICS_SESSION_INDEXES_HPP
#define __ELLIPTICS_SESSION_INDEXES_HPP

#include <time.h>

#include <iostream>

std::ostream &operator <<(std::ostream &out, const dnet_raw_id &v)
{
	out << dnet_dump_id_str(v.id);
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::index_entry &v)
{
	out << "(id: " << v.index << ", data-size: " << v.data.size() << ")";
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
std::ostream &operator <<(std::ostream &out, const std::map<K, V> &v)
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
std::ostream &operator <<(std::ostream &out, const std::pair<K, V> &v)
{
	out << "p{" << v.first << "," << v.second << "}";
	return out;
}

std::ostream &operator <<(std::ostream &out, const ioremap::elliptics::find_indexes_result_entry &v)
{
	out << "re{" << v.id << "," << v.indexes << "}";
	return out;
}

std::ostream &operator <<(std::ostream &out, const dnet_time &tv)
{
	char str[64];
	struct tm tm;

	localtime_r((time_t *)&tv.tsec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	out << str << "." << tv.tnsec / 1000;
	return out;
}

#endif /* __ELLIPTICS_SESSION_INDEXES_HPP */
