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

namespace ioremap { namespace cache {

enum actions {
	ACTION_CACHE,
	ACTION_WRITE,
	ACTION_READ,
	ACTION_ERASE,
	ACTION_LOOKUP,
};

class time_stats_tree_t {
public:
	time_stats_tree_t();
	~time_stats_tree_t();

	void print();

	struct node_t {
		node_t(int action_code): action_code(action_code), time(0) {}

		int action_code;
		long long int time;

		std::unordered_map<int, node_t*> links;
	};

	node_t* root;

private:
	void print(node_t *current_node);
	void erase(node_t* current_node);

};

class time_stats_updater_t {
public:
	typedef time_stats_tree_t::node_t node_t;
	typedef std::chrono::time_point<std::chrono::system_clock> time_point_t;

	time_stats_updater_t(const time_stats_tree_t& t);
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
		measurement(const time_point_t& time, node_t* previous_node): start_time(time),
			previous_node(previous_node) {}

		time_point_t start_time;
		node_t* previous_node;
	};

	void pop_measurement(const time_point_t& end_time = std::chrono::system_clock::now());

	node_t* current_node;
	std::stack<measurement> measurements;
};

}}

#endif // TIME_STATS_HPP
