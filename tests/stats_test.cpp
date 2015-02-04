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

static std::shared_ptr<nodes_data> global_data;

static void destroy_global_data()
{
	global_data.reset();
}

struct test_event {
	std::string		id;
	uint64_t		size;
	double			frequency;
	time_t			last_access;

	typedef const decltype(id) *key_type;
	typedef size_t time_type;

	key_type get_key() const { return &id; }

	uint64_t get_weight() const { return size; }
	void set_weight(uint64_t weight) { size = weight; }

	double get_frequency() const { return frequency; }
	void set_frequency(double freq) { frequency = freq; }

	time_type get_time() const {return last_access; }
	void set_time(time_type time) { last_access = time; }

	inline static int key_compare(const key_type &lhs, const key_type &rhs) {
		return lhs->compare(*rhs);
	}

	inline static bool key_compare_event(const test_event &lhs, const test_event &rhs) {
		return key_compare(lhs.get_key(), rhs.get_key()) < 0;
	}

	inline static bool weight_compare(const test_event &lhs, const test_event &rhs) {
		return lhs.get_weight() < rhs.get_weight();
	}

	inline static int time_compare(const time_type &lhs, const time_type &rhs) {
		if (lhs < rhs) {
			return 1;
		}

		if (lhs > rhs) {
			return -1;
		}

		return 0;
	}
};

#define TOP_K 50
#define EVENTS_LIMIT 1000
#define EVENTS_SIZE (static_cast<int64_t>(EVENTS_LIMIT * sizeof(ioremap::monitor::key_stat_t<test_event>)))
#define PERIOD_IN_SECONDS 300

static void configure_nodes(const std::string &path)
{
    config_data top_params = config_data()
		("top_k", TOP_K)
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

static void test_top_provider_existance()
{
	typedef ioremap::monitor::monitor* MonitorPtr;
	typedef std::shared_ptr<ioremap::monitor::stat_provider> StatPtr;

	dnet_node *node = global_data->nodes[0].get_native();
	MonitorPtr monitor = reinterpret_cast<MonitorPtr>(node->monitor);

	BOOST_CHECK(monitor != nullptr);
	StatPtr provider = monitor->get_statistics().get_provider("top");
	BOOST_CHECK(provider != nullptr);
}

/****************
 Test event_stats
 ****************/
typedef ioremap::monitor::event_stats<test_event> stats_t;

static void test_event_stats_boundary_conditions()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	const time_t expire_time = default_time + PERIOD_IN_SECONDS + 1;
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	stats.get_top(TOP_K, default_time, result);
	BOOST_CHECK(result.empty());

	for(int i = 0; i < 2 * TOP_K; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_K, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_K);

	for(int i = 0; i < 4 * EVENTS_LIMIT; ++i) {
		test_event e{std::to_string(static_cast<long long>(rand())), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	result.clear();
	stats.get_top(4*EVENTS_LIMIT, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), EVENTS_LIMIT);

	result.clear();
	stats.get_top(TOP_K, expire_time, result);
	BOOST_CHECK(result.empty());

	const int few_events = 5;
	BOOST_CHECK(few_events < TOP_K);

	for(int i = 0; i < few_events; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_K, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), few_events);
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

static void test_event_stats_no_time_dependency()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	stats_t stats_rand(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result;

	for(int i = 0; i < TOP_K; ++i) {
		test_event e{"same", default_size, 1., default_time};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_K, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result.back().get_weight(), TOP_K * default_size);

	// monotonically increment event's weight within events_limit
	std::vector<test_event> top_events;
	for(int i = 1; i <= 3 * TOP_K; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), i * default_size, 1., default_time};
		if (i > 2 * TOP_K)
			top_events.push_back(e);
		stats.add_event(e, e.get_time());
	}

	result.clear();
	stats.get_top(TOP_K, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_K);
	BOOST_REQUIRE_EQUAL(events_symmetric_diff(top_events, result), 0);

	// generate events with random weights within events_limit
	std::vector<test_event> min_heap;
	min_heap.reserve(TOP_K);
	std::function<decltype(test_event::weight_compare)> comparator_weight(&test_event::weight_compare);
	for(int i = 0; i < EVENTS_LIMIT; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), rand(), 1., default_time};
		if (min_heap.size() >= TOP_K) {
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

	result.clear();
	stats_rand.get_top(TOP_K, default_time, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_K);
	BOOST_REQUIRE_EQUAL(events_symmetric_diff(min_heap, result), 0);

	// check that statistics doesn't depend on order of key insertion
	std::vector<test_event> test_set;
    for(int i = 1; i < 8; ++i) {
		test_event e{std::to_string(static_cast<long long>(i)), i * default_size, 1., default_time};
		test_set.push_back(e);
	}

	do {
		std::vector<test_event> permut(test_set);
		stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
		for(auto it = permut.cbegin(); it != permut.cend(); ++it) {
			stats.add_event(*it, it->get_time());
		}
		result.clear();
		stats.get_top(TOP_K, default_time, result);
		BOOST_REQUIRE_EQUAL(result.size(), permut.size());
		BOOST_REQUIRE_EQUAL(events_symmetric_diff(result, permut), 0);
	} while (next_permutation(test_set.begin(), test_set.end(), test_event::key_compare_event));
}

static void test_event_stats_with_time_dependency()
{
	const size_t default_size = 100;
	const time_t default_time = time(nullptr);
	stats_t stats(EVENTS_SIZE, PERIOD_IN_SECONDS);
	stats_t stats2(EVENTS_SIZE, PERIOD_IN_SECONDS);
	stats_t stats3(EVENTS_SIZE, PERIOD_IN_SECONDS);
	std::vector<test_event> result, top_events;

	// old events (outside observable period of time) are omitted
	const size_t long_period = 10 * PERIOD_IN_SECONDS;
	for(size_t i = 0; i < long_period; ++i) {
		test_event e{"same", default_size, 1., default_time + i};
		stats.add_event(e, e.get_time());
	}

	stats.get_top(TOP_K, default_time + long_period, result);
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_CHECK(result.back().get_weight() <= PERIOD_IN_SECONDS * default_size);

	// weight of event must be smaller after significant period of silence
	test_event e{"same", default_size, 1., default_time + long_period + PERIOD_IN_SECONDS / 2};
	stats.add_event(e, e.get_time());
	result.clear();	
	stats.get_top(TOP_K, e.get_time(), result);
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_CHECK(result.back().get_weight() <= PERIOD_IN_SECONDS * default_size / 2);

	// small key with regular frequent access must popup in top stats among heavier keys with single access
	for(int i = 0; i < 3 * TOP_K; ++i) {
		size_t size = i % 2 ? default_size : default_size * 10;
		std::string key = i % 2 ? std::string("sum") : std::to_string(static_cast<long long>(i));

		test_event e{key, size, 1., default_time + i};
		stats2.add_event(e, e.get_time());
	}

	result.clear();	
	stats2.get_top(TOP_K, default_time + 3 * TOP_K, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_K);
	BOOST_REQUIRE_EQUAL(*result.front().get_key(), "sum");
	BOOST_CHECK(result.front().get_weight() > result.back().get_weight());
	BOOST_CHECK(result.front().get_frequency() > result.back().get_frequency());

	// if keys have same size and time access pattern, then keys with more frequent access must be in top
	for(int i = 0; i < 5 * TOP_K; ++i) {
		std::string key = std::to_string(static_cast<long long>(i));
		for(int j = 0; j < i+1; ++j) {
			test_event e{key, default_size, 1., default_time + j};
			stats3.add_event(e, e.get_time());
		}
		if (i >= 4 * TOP_K) {
			top_events.push_back({key, default_size, 1., default_time});
		}
	}

	result.clear();
	stats3.get_top(TOP_K, default_time + 5 * TOP_K, result);
	BOOST_REQUIRE_EQUAL(result.size(), TOP_K);
	BOOST_REQUIRE_EQUAL(events_symmetric_diff(top_events, result), 0);
}

bool register_tests(test_suite *suite, node n)
{
	(void) n;
	ELLIPTICS_TEST_CASE_NOARGS(test_top_provider_existance);
	ELLIPTICS_TEST_CASE_NOARGS(test_event_stats_boundary_conditions);
	ELLIPTICS_TEST_CASE_NOARGS(test_event_stats_no_time_dependency);
	ELLIPTICS_TEST_CASE_NOARGS(test_event_stats_with_time_dependency);

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

	test_suite *suite = new test_suite("Local Test Suite");

	configure_nodes(path);

	register_tests(suite, *global_data->node);

	return suite;
}

}

int main(int argc, char *argv[])
{
	atexit(tests::destroy_global_data);
	srand(time(0));
	return unit_test_main(tests::register_tests, argc, argv);
}
