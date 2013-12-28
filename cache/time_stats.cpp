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
	root = new_node(ACTION_CACHE);
}

time_stats_tree_t::~time_stats_tree_t() {
}

rapidjson::Value& time_stats_tree_t::to_json(rapidjson::Value &stat_value,
											 rapidjson::Document::AllocatorType &allocator) {
	return to_json(root, stat_value, allocator);
}

int time_stats_tree_t::get_node_action_code(time_stats_tree_t::p_node_t node) const {
	return nodes[node].action_code;
}

void time_stats_tree_t::set_node_time(time_stats_tree_t::p_node_t node, long long int time) {
	nodes[node].time = time;
}

long long int time_stats_tree_t::get_node_time(time_stats_tree_t::p_node_t node) const {
	return nodes[node].time;
}

bool time_stats_tree_t::node_has_link(time_stats_tree_t::p_node_t node, int action_code) const {
	return nodes[node].links.find(action_code) != nodes[node].links.end();
}

time_stats_tree_t::p_node_t time_stats_tree_t::get_node_link(time_stats_tree_t::p_node_t node, int action_code) const {
	return nodes[node].links.at(action_code);
}

void time_stats_tree_t::add_new_link(time_stats_tree_t::p_node_t node, int action_code) {
	nodes[node].links.emplace(action_code, new_node(action_code));
}

rapidjson::Value &time_stats_tree_t::to_json(p_node_t current_node, rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) {
	stat_value.AddMember("time", (int64_t) get_node_time(current_node), allocator);

	for (auto it = nodes[current_node].links.begin(); it != nodes[current_node].links.end(); ++it) {
		p_node_t next_node = it->second;
		rapidjson::Value subtree_value(rapidjson::kObjectType);
		to_json(next_node, subtree_value, allocator);
		stat_value.AddMember(get_action_name(get_node_action_code(next_node)), subtree_value, allocator);
	}
	return stat_value;
}

time_stats_tree_t::p_node_t time_stats_tree_t::new_node(int action_code) {
	nodes.emplace_back(action_code);
	return nodes.size() - 1;
}

time_stats_updater_t::time_stats_updater_t(time_stats_tree_t &t): current_node(t.root), t(t) {
	measurements.emplace(std::chrono::system_clock::now(), NULL);
}

time_stats_updater_t::~time_stats_updater_t() {
	time_point_t now = std::chrono::system_clock::now();
	while (!measurements.empty()) {
		pop_measurement(now);
	}
}

void time_stats_updater_t::start(const int action_code) {
	if (!t.node_has_link(current_node, action_code)) {
		t.add_new_link(current_node, action_code);
	}
	p_node_t next_node = t.get_node_link(current_node, action_code);
	measurements.emplace(std::chrono::system_clock::now(), current_node);
	current_node = next_node;
}

void time_stats_updater_t::stop(const int action_code) {
	if (t.get_node_action_code(current_node) != action_code) {
		throw std::logic_error("Stopping wrong action");
	}
	pop_measurement();
}

void time_stats_updater_t::pop_measurement(const time_point_t& end_time) {
	measurement previous_measurement = measurements.top();
	measurements.pop();
	t.set_node_time(current_node, t.get_node_time(current_node) + delta(previous_measurement.start_time, end_time));
	current_node = previous_measurement.previous_node;
}

}}
