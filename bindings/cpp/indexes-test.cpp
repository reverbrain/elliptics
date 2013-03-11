#include <elliptics/cppdef.h>

#include <cassert>
#include <sstream>
#include <algorithm>
#include <map>

using namespace ioremap::elliptics;

static inline bool operator <(const dnet_raw_id &a, const dnet_raw_id &b)
{
	return memcmp(a.id, b.id, sizeof(a.id)) < 0;
}

template <typename Container>
Container sorted(const Container &c)
{
	Container tmp(c.begin(), c.end());
	std::sort(tmp.begin(), tmp.end());
	return tmp;
}

enum {
	OBJECT_COUNT = 10,
	TAGS_COUNT = 10
};

static std::string int_to_string(int number)
{
	std::ostringstream out;
	out << number;
	return out.str();
}

namespace index_test {

static std::vector<std::string> objects;
static std::vector<std::string> tags;
static std::map<dnet_raw_id, std::string> hash;

void clear(session &sess)
{
	dnet_io_attr io;
	memset(&io, 0, sizeof(io));
	memset(io.id, 0, sizeof(io.id));
	memset(io.parent, 0xff, sizeof(io.id));

	try {
		sess.remove_data_range(io, 2);
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

void test_1(session &sess)
{
	std::map<std::string, std::vector<std::string> > cache;
	for (size_t i = 0; i < 10000; ++i) {
		const bool update = (rand() & 1);
		if (update) {
			const std::string &object = objects[rand() % OBJECT_COUNT];

			std::vector<std::string> object_tags = tags;
			const size_t count = rand() % TAGS_COUNT;
			std::random_shuffle(object_tags.begin(), object_tags.end());
			object_tags.resize(count);

			std::cerr << i << " update: " << object << " to " << sorted(object_tags) << std::endl;

			int result = 0;
			try {
				sess.update_indexes(object, object_tags);
			} catch (error &e) {
				result = e.error_code();
			} catch (std::bad_alloc &e) {
				result = -ENOMEM;
			}

			assert_perror(result);

			std::sort(object_tags.begin(), object_tags.end());
			cache[object] = object_tags;
		} else { // find
			std::vector<std::string> object_tags = tags;
			const size_t count = rand() % TAGS_COUNT;
			std::random_shuffle(object_tags.begin(), object_tags.end());
			object_tags.resize(count);

			std::cerr << i << " find: " << sorted(object_tags) << std::endl;

			std::vector<dnet_raw_id> results;
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

			std::vector<std::string> valid_results;
//			key tmp;
			for (auto it = cache.begin(); it != cache.end(); ++it) {
				const std::vector<std::string> &tags = it->second;
				bool ok = !tags.empty() && !object_tags.empty();
				for (auto jt = object_tags.begin(); jt != object_tags.end(); ++jt) {
					if (std::find(tags.begin(), tags.end(), *jt) == tags.end()) {
						ok = false;
						break;
					}
				}
				if (ok) {
					valid_results.push_back(it->first);
				}
			}
			std::cerr << sorted(valid_results) << " vs " << sorted(results) << std::endl;
			assert(valid_results.size() == results.size());
		}
	}
}

}

int main(int argc, char *argv[])
{
	// Results must be reproducable
	srand(0xd34db33f);

	using namespace index_test;

	(void) argc;
	(void) argv;

	file_logger logger("/dev/stderr", DNET_LOG_DATA);
	node n(logger);

	n.add_remote("localhost", 1025);

	session sess(n);
	std::vector<int> groups = { 1, 2, 3 };
	sess.set_groups(groups);

	for (size_t i = 0; i < OBJECT_COUNT; ++i)
		objects.push_back("object_" + int_to_string(i + 1));
	for (size_t i = 0; i < TAGS_COUNT; ++i)
		tags.push_back("tag_" + int_to_string(i + 1));

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

	clear(sess);

	test_1(sess);
}
