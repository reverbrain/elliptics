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

#include "time_stats.hpp"

namespace ioremap { namespace cache {

const char* actions_names[]{
	"CACHE_ACTION",
	"WRITE_ACTION",
	"READ_ACTION",
	"ERASE_ACTION",
	"LOOKUP_ACTION",
};

const char* get_action_name(const int action_code) {
	return actions_names[action_code];
}

time_stats_tree_t::time_stats_tree_t() {
	root = new node_t(-1);
}

time_stats_tree_t::~time_stats_tree_t() {
	print();
	erase(root);
}

void time_stats_tree_t::print() {
	print(root);
}

void time_stats_tree_t::print(node_t* current_node) {
	std::cout << get_action_name(current_node->action_code) << " " << current_node->time << std::endl;
	for (auto it = current_node->links.begin(); it != current_node->links.end(); ++it) {
		print(it->second);
	}
}

void time_stats_tree_t::erase(time_stats_tree_t::node_t *current_node) {
	for (auto it = current_node->links.begin(); it != current_node->links.end(); ++it) {
		erase(it->second);
	}
	delete current_node;
}

time_stats_updater_t::time_stats_updater_t(const time_stats_tree_t &t): current_node(t.root) {
}

time_stats_updater_t::~time_stats_updater_t() {
	time_point_t now = std::chrono::system_clock::now();
	while (!measurements.empty()) {
		pop_measurement(now);
	}
}

void time_stats_updater_t::start(const int action_code) {
	if (current_node->links.find(action_code) == current_node->links.end()) {
		current_node->links.emplace(action_code, new node_t(action_code));
	}
	node_t* next_node = current_node->links[action_code];
	measurements.emplace(std::chrono::system_clock::now(), current_node);
	current_node = next_node;
}

void time_stats_updater_t::stop(const int action_code) {
	if (current_node->action_code != action_code) {
		throw std::logic_error("Stopping wrong action");
	}
	pop_measurement();
}

void time_stats_updater_t::pop_measurement(const time_point_t& end_time) {
	measurement previous_measurement = measurements.top();
	measurements.pop();

	current_node->time += delta(previous_measurement.start_time, end_time);
	current_node = previous_measurement.previous_node;
}

}}
