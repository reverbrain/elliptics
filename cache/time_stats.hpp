/*
* 2013+ Copyright (c) Andrey Kashin <kashin.andrej@gmail.com>
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

#ifndef TIME_STATS_HPP
#define TIME_STATS_HPP

#include <stack>
#include <chrono>
#include <unordered_map>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <mutex>

#include "../monitor/rapidjson/document.h"
#include "../monitor/rapidjson/writer.h"
#include "../monitor/rapidjson/stringbuffer.h"

namespace ioremap { namespace cache {

enum actions {
	ACTION_CACHE,
	ACTION_WRITE,
	ACTION_READ,
	ACTION_REMOVE,
	ACTION_LOOKUP,
};

class time_stats_tree_t {
public:
	time_stats_tree_t();
	~time_stats_tree_t();

	rapidjson::Value& to_json(rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator);

	struct node_t;
	typedef size_t p_node_t;
	struct node_t {
		node_t(int action_code): action_code(action_code), time(0) {}

		int action_code;
		long long int time;

		std::unordered_map<int, p_node_t> links;
	};

	int get_node_action_code(p_node_t node) const;
	void set_node_time(p_node_t node, long long time);
	long long int get_node_time(p_node_t node) const;
	bool node_has_link(p_node_t node, int action_code) const;
	p_node_t get_node_link(p_node_t node, int action_code) const;
	void add_new_link(p_node_t node, int action_code);

	p_node_t root;

private:
	rapidjson::Value& to_json(p_node_t current_node, rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator);

	p_node_t new_node(int action_code);

	std::vector<node_t> nodes;
};

class time_stats_updater_t {
public:
	typedef time_stats_tree_t::node_t node_t;
	typedef time_stats_tree_t::p_node_t p_node_t;
	typedef std::chrono::time_point<std::chrono::system_clock> time_point_t;

	time_stats_updater_t(time_stats_tree_t &t);
	~time_stats_updater_t();

	void start(const int action_code);
	void stop(const int action_code);

private:
	template<class Period = std::chrono::microseconds>
	long long int delta(time_point_t& start, const time_point_t& end) const
	{
		return (std::chrono::duration_cast<Period> (end - start)).count();
	}

	struct measurement {
		measurement(const time_point_t& time, p_node_t previous_node): start_time(time),
			previous_node(previous_node) {}

		time_point_t start_time;
		p_node_t previous_node;
	};

	void pop_measurement(const time_point_t& end_time = std::chrono::system_clock::now());

	p_node_t current_node;
	std::stack<measurement> measurements;
	time_stats_tree_t& t;
};

}}

#endif // TIME_STATS_HPP
