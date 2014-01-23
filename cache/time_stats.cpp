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
	"ACTION_CACHE",
	"ACTION_WRITE",
	"ACTION_READ",
	"ACTION_REMOVE",
	"ACTION_LOOKUP",
	"ACTION_LOCK",
	"ACTION_FIND",
	"ACTION_ADD_TO_PAGE",
	"ACTION_RESIZE_PAGE",
	"ACTION_SYNC_AFTER_APPEND",
	"ACTION_WRITE_APPEND_ONLY",
	"ACTION_WRITE_AFTER_APPEND_ONLY",
	"ACTION_POPULATE_FROM_DISK",
	"ACTION_CLEAR",
	"ACTION_LIFECHECK",
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
											 rapidjson::Document::AllocatorType &allocator) const {
	return to_json(root, stat_value, allocator);
}

int time_stats_tree_t::get_node_action_code(time_stats_tree_t::p_node_t node) const {
	std::lock_guard<std::mutex> guard(lock);
	return nodes[node].action_code;
}

void time_stats_tree_t::set_node_time(time_stats_tree_t::p_node_t node, long long int time) {
	std::lock_guard<std::mutex> guard(lock);
	nodes[node].time = time;
}

long long int time_stats_tree_t::get_node_time(time_stats_tree_t::p_node_t node) const {
	std::lock_guard<std::mutex> guard(lock);
	return nodes[node].time;
}

bool time_stats_tree_t::node_has_link(time_stats_tree_t::p_node_t node, int action_code) const {
	std::lock_guard<std::mutex> guard(lock);
	return nodes[node].links.find(action_code) != nodes[node].links.end();
}

time_stats_tree_t::p_node_t time_stats_tree_t::get_node_link(time_stats_tree_t::p_node_t node, int action_code) const {
	std::lock_guard<std::mutex> guard(lock);
	return nodes[node].links.at(action_code);
}

void time_stats_tree_t::add_new_link(time_stats_tree_t::p_node_t node, int action_code) {
	p_node_t action_node = new_node(action_code);
	std::lock_guard<std::mutex> guard(lock);
	nodes[node].links.emplace(action_code, action_node);
}

void time_stats_tree_t::merge_into(time_stats_tree_t &another_tree) const {
	merge_into(root, another_tree.root, another_tree);
}

rapidjson::Value &time_stats_tree_t::to_json(p_node_t current_node, rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
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
	std::lock_guard<std::mutex> guard(lock);
	nodes.emplace_back(action_code);
	return nodes.size() - 1;
}

void time_stats_tree_t::merge_into(time_stats_tree_t::p_node_t lhs_node,
								   time_stats_tree_t::p_node_t rhs_node, time_stats_tree_t &rhs_tree) const {
	rhs_tree.set_node_time(rhs_node, rhs_tree.get_node_time(rhs_node) + get_node_time(lhs_node));

	for (auto it = nodes[lhs_node].links.begin(); it != nodes[lhs_node].links.end(); ++it) {
		int action_code = it->first;
		p_node_t lhs_next_node = it->second;
		if (!rhs_tree.node_has_link(rhs_node, action_code)) {
			rhs_tree.add_new_link(rhs_node, action_code);
		}
		p_node_t rhs_next_node = rhs_tree.get_node_link(rhs_node, action_code);
		merge_into(lhs_next_node, rhs_next_node, rhs_tree);
	}
}

time_stats_updater_t::time_stats_updater_t(): t(nullptr), depth(0) {
	measurements.emplace(std::chrono::system_clock::now(), NULL);
}

time_stats_updater_t::time_stats_updater_t(time_stats_tree_t &t) {
	set_time_stats_tree(t);
	measurements.emplace(std::chrono::system_clock::now(), NULL);
}

time_stats_updater_t::~time_stats_updater_t() {
	if (depth != 0) {
		throw std::logic_error("~time_stats_updater(): extra measurements");
	}
	while (!measurements.empty()) {
		pop_measurement();
	}
}

void time_stats_updater_t::set_time_stats_tree(time_stats_tree_t &t) {
	current_node = t.root;
	this->t = &t;
	depth = 0;
}

bool time_stats_updater_t::has_time_stats_tree() const {
	return (t != nullptr);
}

void time_stats_updater_t::start(const int action_code) {
	start(action_code, std::chrono::system_clock::now());
}

void time_stats_updater_t::start(const int action_code, const time_stats_updater_t::time_point_t& start_time) {
	if (!t->node_has_link(current_node, action_code)) {
		t->add_new_link(current_node, action_code);
	}
	p_node_t next_node = t->get_node_link(current_node, action_code);
	measurements.emplace(start_time, current_node);

	current_node = next_node;
	++depth;
}

void time_stats_updater_t::stop(const int action_code) {
	if (t->get_node_action_code(current_node) != action_code) {
		throw std::logic_error("Stopping wrong action");
	}
	pop_measurement();
}

size_t time_stats_updater_t::get_depth() const {
	return depth;
}

void time_stats_updater_t::pop_measurement(const time_point_t& end_time) {
	measurement previous_measurement = measurements.top();
	measurements.pop();
	t->set_node_time(current_node, t->get_node_time(current_node) + delta(previous_measurement.start_time, end_time));
	current_node = previous_measurement.previous_node;
	--depth;
}

action_guard::action_guard(time_stats_updater_t *updater, int action_code): updater(updater), action_code(action_code) {
	updater->start(action_code);
}

action_guard::~action_guard() {
	updater->stop(action_code);
}

}}
