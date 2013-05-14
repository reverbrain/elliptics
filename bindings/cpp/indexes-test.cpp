#include <elliptics/cppdef.h>

#ifdef NDEBUG
# undef NDEBUG
#endif

#include <cassert>
#include <sstream>
#include <algorithm>
#include <map>
#include <iostream>

using namespace ioremap::elliptics;

namespace index_test {

template <int is_hash_sorted>
struct index_comparator
{
	inline bool operator() (const dnet_raw_id &a, const dnet_raw_id &b) const
	{
		if (is_hash_sorted)
			return convert(a) < convert(b);
		else
			return memcmp(a.id, b.id, sizeof(a.id)) < 0;
	}

	inline bool operator() (const index_entry &a, const index_entry &b) const
	{
		ssize_t cmp = is_hash_sorted
			? convert(a.index).compare(convert(b.index))
			: memcmp(b.index.id, a.index.id, sizeof(b.index.id));
		if (cmp == 0) {
			cmp = a.data.size() - b.data.size();
			if (cmp == 0) {
				cmp = memcmp(a.data.data(), b.data.data(), a.data.size());
			}
		}
		return cmp < 0;
	}

	inline bool operator() (const find_indexes_result_entry &a, const find_indexes_result_entry &b) const
	{
		return operator() (a.id, b.id);
	}

	inline bool operator() (const std::pair<dnet_raw_id, data_pointer> &a, const std::pair<dnet_raw_id, data_pointer> &b) const
	{
		return operator() (a.first, b.first);
	}

	template <typename T>
	inline bool operator() (const T &a, const T &b) const
	{
		return a < b;
	}

	std::string convert(const dnet_raw_id &id) const;
};

static std::vector<std::string> objects;
static std::vector<std::string> tags;
static std::map<dnet_raw_id, std::string, index_comparator<0> > hash;

template <int bla>
std::string index_comparator<bla>::convert(const dnet_raw_id &id) const
{
	static char dump_id_str[2 * DNET_ID_SIZE + 1];
	auto it = hash.find(id);
	if (it == hash.end())
		return dnet_dump_id_len_raw(id.id, DNET_ID_SIZE, dump_id_str);
	else
		return it->second;
}

template <typename Container>
Container sorted(const Container &c);

template <typename K, typename V>
std::pair<K, V> sorted(const std::pair<K, V> &c)
{
	return std::pair<K, V>(sorted(c.first), sorted(c.second));
}

template <typename Container>
Container sorted(const Container &c)
{
	Container tmp(c.begin(), c.end());
	std::sort(tmp.begin(), tmp.end(), index_comparator<1>());
	for (auto it = tmp.begin(); it != tmp.end(); ++it)
		*it = sorted(*it);
	return tmp;
}

template <>
std::string sorted<std::string>(const std::string &c)
{
	return c;
}

template <>
find_indexes_result_entry sorted<find_indexes_result_entry>(const find_indexes_result_entry &c)
{
	find_indexes_result_entry copy = { c.id, sorted(c.indexes) };
	return copy;
}

template <>
dnet_raw_id sorted<dnet_raw_id>(const dnet_raw_id &c)
{
	return c;
}

template <>
data_pointer sorted<data_pointer>(const data_pointer &c)
{
	return c;
}

enum {
	OBJECT_COUNT = 10,
	TAGS_COUNT = 10
};

template <typename T>
static std::string to_string(const T &number)
{
	std::ostringstream out;
	out << number;
	return out.str();
}

void clear(session &sess)
{
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memset(io.id, 0, sizeof(io.id));
	memset(io.parent, 0xff, sizeof(io.id));

	try {
		sess.remove_data_range(io, 2).wait();
	} catch (...) {
	}

//	std::vector<std::string> no_tags;
//	for (size_t i = 0; i < objects.size(); ++i) {
//		int result = sess.update_indexes(objects[i], no_tags);
//		assert_perror(result);
//	}
}

std::ostream &operator <<(std::ostream &out, const dnet_raw_id &v)
{
	auto it = hash.find(v);
	if (it == hash.end())
		out << dnet_dump_id_str(v.id);
	else
		out << it->second;
	return out;
}

std::ostream &operator <<(std::ostream &out, const index_entry &v)
{
	out << "(" << v.index << ",\"" << v.data.to_string() << "\")";
	return out;
}

std::ostream &operator <<(std::ostream &out, const data_pointer &v)
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

std::ostream &operator <<(std::ostream &out, const find_indexes_result_entry &v)
{
	out << "(" << v.id << "," << v.indexes << ")";
	return out;
}

std::string create_data()
{
	const size_t length = 5 + (rand() % 10);
	std::string str;
	str.resize(length);
	for (size_t i = 0; i < length; ++i)
		str[i] = 'a' + (rand() % 26);
	return str;
}

void test_1(session &sess)
{
	std::map<std::string, std::map<std::string, std::string> > cache;
	for (size_t i = 0; i < 10000; ++i) {
		const bool update = (rand() & 1);
		if (update) {
			const std::string &object = objects[rand() % OBJECT_COUNT];

			std::vector<std::string> object_tags = tags;
			const size_t count = rand() % TAGS_COUNT;
			std::random_shuffle(object_tags.begin(), object_tags.end());
			object_tags.resize(count);
			std::vector<data_pointer> object_datas;
			object_datas.resize(count);
			auto &entry = cache[object];
			entry.clear();
			for (size_t j = 0; j < count; ++j) {
				std::string data = create_data();
				entry[object_tags[j]] = data;
				object_datas[j] = data_pointer::copy(data.c_str(), data.size());
			}

			std::cerr << i << " update: " << object << " to " << sorted(object_tags) << std::endl;

			int result = 0;
			try {
				sess.update_indexes(object, object_tags, object_datas).get();
			} catch (error &e) {
				std::cerr << e.what() << std::endl;
				result = e.error_code();
			} catch (std::bad_alloc &e) {
				result = -ENOMEM;
			}

			assert_perror(result);
		} else { // find
			std::vector<std::string> object_tags = tags;
			const size_t count = rand() % TAGS_COUNT;
			std::random_shuffle(object_tags.begin(), object_tags.end());
			object_tags.resize(count);

			std::cerr << i << " find: " << sorted(object_tags) << std::endl;

			std::vector<find_indexes_result_entry> results;
			int result = 0;
			try {
				results = sess.find_indexes(object_tags);
			} catch (error &e) {
				result = e.error_code();
			} catch (std::bad_alloc &e) {
				result = -ENOMEM;
			}

			if (result != -2)
				assert_perror(result);

			std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::string> > > > valid_results;
			for (auto it = cache.begin(); it != cache.end(); ++it) {
				std::pair<std::string, std::vector<std::pair<std::string, std::string> > > entry;
				const std::map<std::string, std::string> &tags = it->second;
				entry.first = it->first;
				bool ok = !tags.empty() && !object_tags.empty();
				for (auto jt = object_tags.begin(); jt != object_tags.end(); ++jt) {
					auto kt = tags.find(*jt);
					if (kt == tags.end()) {
						ok = false;
						break;
					}
					entry.second.push_back(std::make_pair(kt->first, kt->second));
				}
				if (ok) {
					valid_results.push_back(entry);
				}
			}
			std::string valid_results_str = to_string(sorted(valid_results));
			std::string results_str = to_string(sorted(results));
			std::cerr << valid_results_str << " vs " << results_str << std::endl;
			assert(valid_results.size() == results.size());
			assert(valid_results_str == results_str);
		}
//		std::cerr << "cache: " << cache << std::endl;
	}
}

}

int main(int argc, char *argv[])
{
	// Results must be reproducible
	srand(0xd34db33f);

	using namespace index_test;

	(void) argc;
	(void) argv;

	file_logger logger("/dev/stderr", DNET_LOG_DATA);
	node n(logger);

	n.add_remote("localhost", 1025);

	session sess(n);
	std::vector<int> groups = { 2 };
	sess.set_groups(groups);

	for (size_t i = 0; i < OBJECT_COUNT; ++i)
		objects.push_back("object_" + to_string(i + 1));
	for (size_t i = 0; i < TAGS_COUNT; ++i)
		tags.push_back("tag_" + to_string(i + 1));

	for (auto it = objects.begin(); it != objects.end(); ++it) {
		key tmp = *it;
		tmp.transform(sess);
		dnet_raw_id id;
		memcpy(id.id, tmp.id().id, sizeof(id.id));
		hash[id] = *it;
	}
	for (auto it = tags.begin(); it != tags.end(); ++it) {
		key tmp = *it;
		tmp.transform(sess);
		dnet_raw_id id;
		memcpy(id.id, tmp.id().id, sizeof(id.id));
		hash[id] = *it;
	}

//	clear(sess);

	test_1(sess);
}
