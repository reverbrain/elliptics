/*
 * 2015+ Copyright (c) Budnik Andrey <budnik27@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "test_base.hpp"
#include "../monitor/event_stats.hpp"
#include "../monitor/monitor.hpp"

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

class test_event;

}  /* namespace tests */

namespace ioremap { namespace cache {

template<>
struct treap_node_traits<tests::test_event>
{
	typedef const std::string* key_type;
	typedef size_t priority_type;
};

}}  /* namespace ioremap::cache */

namespace tests {

static std::shared_ptr<nodes_data> global_data;

static void destroy_global_data()
{
	global_data.reset();
}

class test_event : public ioremap::cache::treap_node_t<test_event> {
public:
	test_event() = default;
	test_event(const std::string& id, uint64_t size, double frequency, time_t last_access)
	: m_id(id), m_size(size), m_frequency(frequency), m_last_access(last_access)
	{}

	uint64_t get_weight() const { return m_size; }
	void set_weight(uint64_t weight) { m_size = weight; }

	double get_frequency() const { return m_frequency; }
	void set_frequency(double freq) { m_frequency = freq; }

	time_t get_time() const {return m_last_access; }
	void set_time(time_t time) { m_last_access = time; }

	inline static bool key_compare_event(const test_event &lhs, const test_event &rhs) {
		return key_compare(lhs.get_key(), rhs.get_key()) < 0;
	}

	inline static bool weight_compare(const test_event &lhs, const test_event &rhs) {
		return lhs.get_weight() < rhs.get_weight();
	}

	// treap_node_t
	typedef ioremap::cache::treap_node_traits<test_event>::key_type key_type;
	typedef ioremap::cache::treap_node_traits<test_event>::priority_type priority_type;

	key_type get_key() const { return &m_id; }
	priority_type get_priority() const { return m_last_access; }

	inline static int key_compare(const key_type &lhs, const key_type &rhs) {
		return lhs->compare(*rhs);
	}

	inline static int priority_compare(const priority_type &lhs, const priority_type &rhs) {
		if (lhs < rhs) {
			return 1;
		}

		if (lhs > rhs) {
			return -1;
		}

		return 0;
	}

private:
	std::string		m_id;
	uint64_t		m_size;
	double			m_frequency;
	time_t			m_last_access;
};

#define TOP_LENGTH 50
#define EVENTS_LIMIT 1000
#define EVENTS_SIZE (static_cast<int64_t>(EVENTS_LIMIT * sizeof(test_event)))
#define PERIOD_IN_SECONDS 300

static void configure_nodes(const std::string &path)
{
	config_data top_params = config_data()
		("top_length", TOP_LENGTH)
		("events_size", EVENTS_SIZE)
		("period_in_seconds", PERIOD_IN_SECONDS);

	start_nodes_config start_config(results_reporter::get_stream(), std::vector<server_config>({
		server_config::default_value().apply_options(config_data()
			("group", 5)
			("monitor_top", top_params)
		)
	}), path);

	global_data = start_nodes(start_config);
}

/*
 * Top statistics handler must exist, if "top" section in "monitor" section in config
 * exists. Node's configuration happened in configure_node() function above.
 */
static void test_top_statistics_existence()
{
	dnet_node *node = global_data->nodes[0].get_native();
	auto monitor = ioremap::monitor::get_monitor(node);
	BOOST_CHECK(monitor != nullptr);

	auto top_stats = monitor->get_statistics().get_top_stats();
	BOOST_CHECK(top_stats != nullptr);
}

/****************
 Test event_stats
 ****************/
typedef ioremap::monitor::event_stats<test_event> stats_t;

static void test_empty_top()
{
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	stats.get_top(TOP_LENGTH, default_time, result);
	BOOST_CHECK_MESSAGE(result.empty(), "get_top must return empty list, if no events were added");
}

static void test_top_list_result_limit()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// insert different items at the same time and with the same weight
	for(int i = 0; i < 2 * TOP_LENGTH; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time, result);
	BOOST_REQUIRE_MESSAGE(result.size() == TOP_LENGTH, "get_top must return no more events than was requested");
}

static void test_top_list_result_boundary()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	const int few_events = 5;
	BOOST_CHECK_MESSAGE(TOP_LENGTH > few_events, "it is necessary to request more events than were added");

	// insert different items at the same time and with the same weight
	for(int i = 0; i < few_events; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time, result);
	BOOST_REQUIRE_MESSAGE(result.size() == few_events, "get_top should not return more events, than were added");
}

static void test_top_list_capacity_limit()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// insert different items at the same time and with the same weight
	for(int i = 0; i < 4 * EVENTS_LIMIT; ++i) {
		test_event e{std::to_string(static_cast<long long>(rand())), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(4*EVENTS_LIMIT, default_time, result);
	BOOST_REQUIRE_MESSAGE(result.size() == EVENTS_LIMIT, "get_top must return no more events than EVENTS_LIMIT");
}

static void test_all_events_expiration()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	const time_t expire_time = default_time + PERIOD_IN_SECONDS + 1;
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// insert different items at the same time and with the same weight
	for(int i = 0; i < EVENTS_LIMIT; ++i) {
		test_event e{std::to_string(static_cast<long long>(rand())), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, expire_time, result);
	BOOST_CHECK_MESSAGE(result.empty(), "all events must be expired since expire_time elapsed");
}

template<typename container_t>
static size_t events_symmetric_diff(container_t &fst, container_t &snd)
{
	std::sort(fst.begin(), fst.end(), test_event::key_compare_event);
	std::sort(snd.begin(), snd.end(), test_event::key_compare_event);

	std::vector<test_event> diff(fst.size() + snd.size());
	auto it = std::set_symmetric_difference(fst.begin(), fst.end(),
					        snd.begin(), snd.end(),
					        diff.begin(), test_event::key_compare_event);
	return std::distance(diff.begin(), it);
}

static void test_same_event_many_insertions()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// insert same items at the same time and with the same weight
	for(int i = 0; i < TOP_LENGTH; ++i) {
		test_event e{"same", default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time, result);
	BOOST_REQUIRE_MESSAGE(result.size() == 1, "one and only one element must be in top");
	BOOST_REQUIRE_MESSAGE(result.back().get_weight() == TOP_LENGTH * default_size,
			      "event total weight must be incremented every time element inserted");
}

static void test_insertion_with_increasing_weight()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// monotonically increment event's weight
	std::vector<test_event> top_events;
	for(int i = 1; i <= 3 * TOP_LENGTH; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), i * default_size, 1., default_time};
		if (i > 2 * TOP_LENGTH)
			top_events.push_back(e);
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_LENGTH);
	BOOST_REQUIRE_MESSAGE(events_symmetric_diff(top_events, result) == 0,
			      "last added events are heaviest => they must appear in get_top result");
}

static void test_insertion_with_random_weight()
{
	const time_t default_time = time(nullptr);
	stats_t stats_rand(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// generate events with random weights, use min_heap to find top (heaviest) events
	std::vector<test_event> min_heap;
	min_heap.reserve(TOP_LENGTH);
	std::function<decltype(test_event::weight_compare)> comparator_weight(&test_event::weight_compare);
	for(int i = 0; i < EVENTS_LIMIT; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), static_cast<uint64_t>(rand()), 1., default_time};
		if (min_heap.size() >= TOP_LENGTH) {
			if (min_heap.front().get_weight() < e.get_weight()) {
				std::pop_heap(min_heap.begin(), min_heap.end(), std::not2(comparator_weight));
				min_heap.back() = e;
				std::push_heap(min_heap.begin(), min_heap.end(), std::not2(comparator_weight));
			}
		} else {
			min_heap.push_back(e);
			std::push_heap(min_heap.begin(), min_heap.end(), std::not2(comparator_weight));
		}
		stats_rand.add_event(e, e.get_time());
	}

	stats_rand.get_top(TOP_LENGTH, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_LENGTH);
	BOOST_REQUIRE_MESSAGE(events_symmetric_diff(min_heap, result) == 0,
			      "heaviest events must be in top list");
}

static void test_event_insertion_order_independence()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);

	// check that statistics doesn't depend on order of key insertion
	std::vector<test_event> test_set;
	for(int i = 1; i < 8; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), i * default_size, 1., default_time};
		test_set.push_back(e);
	}

	do {
		stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
		std::vector<test_event> result;
		std::vector<test_event> permut(test_set);
		for(auto it = permut.cbegin(); it != permut.cend(); ++it) {
			stats.add_event(*it, it->get_time());
		}
		stats.get_top(TOP_LENGTH, default_time, result);
		BOOST_REQUIRE_MESSAGE(result.size() == permut.size(),
				    "result must contain all inserted events");
		BOOST_REQUIRE_MESSAGE(events_symmetric_diff(result, permut) == 0,
				      "order of insertion should not impact on get_top results");
	} while (next_permutation(test_set.begin(), test_set.end(), test_event::key_compare_event));
}

static void test_event_weight_attenuation()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	// all events describe access to the same key with the same size, but at different period of time
	// during time window much larger than PERIOD_IN_SECONDS.
	const size_t long_period = 10 * PERIOD_IN_SECONDS;
	for(size_t i = 0; i < long_period; ++i) {
		test_event e{"same", default_size, 1., default_time + static_cast<time_t>(i)};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time + long_period, result);
	BOOST_REQUIRE_MESSAGE(result.size() == 1, "one and only one element must be in top");
	BOOST_CHECK_MESSAGE(result.back().get_weight() <= PERIOD_IN_SECONDS * default_size,
			    "old events (outside observable period of time) shouldn't impact on event weight");

	// Added single event with the "same" key
	// after PERIOD_IN_SECONDS / 2 (half window length) since last event were added in previous test.
	test_event e{"same", default_size, 1., default_time + static_cast<time_t>(long_period + PERIOD_IN_SECONDS / 2)};
	stats.add_event(e, e.get_time());
	result.clear();
	stats.get_top(TOP_LENGTH, e.get_time(), result);
	BOOST_CHECK_MESSAGE(result.back().get_weight() <= PERIOD_IN_SECONDS * default_size / 2,
			    "weight of event must be proportionally smaller after significant period of silence, "
			    "because older events are outdated (outside time window)");
}

static void test_frequent_access_among_heavy_keys()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result, top_events;
	std::string key;
	size_t size;

	// half of inserted events reflects access to the "same" single key,
	// other half of events reflects access to different keys.
	for(int i = 0; i < 3 * TOP_LENGTH; ++i) {
		if (i % 2) {
			key = std::string("same");
			size = default_size;
		} else {
			key = std::to_string(static_cast<long long>(i));
			size = default_size * 10;
		}

		test_event e{key, size, 1., default_time + i};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_LENGTH, default_time + 3 * TOP_LENGTH, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_LENGTH);
	BOOST_REQUIRE_MESSAGE(*result.front().get_key() == "same",
			      "key 'same' with regular frequent access must be first in top list");
	BOOST_CHECK_MESSAGE(result.front().get_frequency() > result.back().get_frequency(),
			    "key 'same' frequency must be greater then any other key");
}

static void test_frequent_access()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result, top_events;

	// all inserted events have same size
	for(int i = 0; i < 5 * TOP_LENGTH; ++i) {
		std::string key = std::to_string(static_cast<long long>(i));
		// access to i-th key occurs i+1 times
		for(int j = 0; j < i+1; ++j) {
			test_event e{key, default_size, 1., default_time + j};
			stats.add_event(e, e.get_time());
		}
		if (i >= 4 * TOP_LENGTH) {
			test_event e{key, default_size, 1., default_time};
			top_events.push_back(e);
		}
	}

	stats.get_top(TOP_LENGTH, default_time + 5 * TOP_LENGTH, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_LENGTH);
	BOOST_REQUIRE_MESSAGE(events_symmetric_diff(top_events, result) == 0,
			      "if keys have same size and time access pattern, "
			      "then keys with more frequent access must be in top");
}

bool register_tests(test_suite *suite)
{
	ELLIPTICS_TEST_CASE_NOARGS(test_top_statistics_existence);
	ELLIPTICS_TEST_CASE_NOARGS(test_empty_top);
	ELLIPTICS_TEST_CASE_NOARGS(test_top_list_result_limit);
	ELLIPTICS_TEST_CASE_NOARGS(test_top_list_result_boundary);
	ELLIPTICS_TEST_CASE_NOARGS(test_top_list_capacity_limit);
	ELLIPTICS_TEST_CASE_NOARGS(test_all_events_expiration);
	ELLIPTICS_TEST_CASE_NOARGS(test_same_event_many_insertions);
	ELLIPTICS_TEST_CASE_NOARGS(test_insertion_with_increasing_weight);
	ELLIPTICS_TEST_CASE_NOARGS(test_insertion_with_random_weight);
	ELLIPTICS_TEST_CASE_NOARGS(test_event_insertion_order_independence);
	ELLIPTICS_TEST_CASE_NOARGS(test_event_weight_attenuation);
	ELLIPTICS_TEST_CASE_NOARGS(test_frequent_access_among_heavy_keys);
	ELLIPTICS_TEST_CASE_NOARGS(test_frequent_access);

	return true;
}

boost::unit_test::test_suite *register_tests(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::string path;

	generic.add_options()
			("help", "This help message")
			("path", bpo::value(&path), "Path where to store everything")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return NULL;
	}

	configure_nodes(path);

	test_suite *suite = new test_suite("event statistics test suite");
	register_tests(suite);

	return suite;
}

}

int main(int argc, char *argv[])
{
	atexit(tests::destroy_global_data);
	srand(time(0));
	return unit_test_main(tests::register_tests, argc, argv);
}
