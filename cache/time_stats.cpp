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

#include <elliptics/interface.h>

namespace ioremap { namespace cache {

actions_set_t::actions_set_t() {
}

actions_set_t::~actions_set_t() {
}

int actions_set_t::define_new_action(const std::string &action_name) {
	int action_code = actions_names.size();
	actions_names.insert(make_pair(action_code, action_name));
	return action_code;
}

std::string actions_set_t::get_action_name(int action_code) const {
	return actions_names.at(action_code);
}

time_stats_tree_t::time_stats_tree_t(const actions_set_t &actions_set): actions_set(actions_set) {
	root = new_node(-1);
}

time_stats_tree_t::~time_stats_tree_t() {
}

rapidjson::Value& time_stats_tree_t::to_json(rapidjson::Value &stat_value,
											 rapidjson::Document::AllocatorType &allocator) const {
	return to_json(root, stat_value, allocator);
}

int time_stats_tree_t::get_node_action_code(time_stats_tree_t::p_node_t node) const {
	return nodes[node].action_code;
}

void time_stats_tree_t::set_node_time(time_stats_tree_t::p_node_t node, long long int time) {
	nodes[node].time = time;
}

void time_stats_tree_t::inc_node_time(time_stats_tree_t::p_node_t node, long long delta) {
	nodes[node].time += delta;
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

time_stats_tree_t::p_node_t time_stats_tree_t::add_new_link(time_stats_tree_t::p_node_t node, int action_code) {
	p_node_t action_node = new_node(action_code);
	nodes[node].links.insert(std::make_pair(action_code, action_node));
	return action_node;
}

time_stats_tree_t::p_node_t time_stats_tree_t::add_new_link_if_missing(time_stats_tree_t::p_node_t node, int action_code) {
	auto link = nodes[node].links.find(action_code);
	if (link == nodes[node].links.end()) {
		return add_new_link(node, action_code);
	}
	return link->second;
}

void time_stats_tree_t::merge_into(time_stats_tree_t &another_tree) const {
	merge_into(root, another_tree.root, another_tree);
}

time_stats_tree_t time_stats_tree_t::diff_from(time_stats_tree_t &another_tree) const {
	time_stats_tree_t diff_tree = *this;
	another_tree.substract_from(diff_tree);
	return std::move(diff_tree);
}

void time_stats_tree_t::substract_from(time_stats_tree_t &another_tree) const {
	return substract_from(root, another_tree.root, another_tree);
}

rapidjson::Value &time_stats_tree_t::to_json(p_node_t current_node, rapidjson::Value &stat_value, rapidjson::Document::AllocatorType &allocator) const {
	stat_value.AddMember("time", (int64_t) get_node_time(current_node), allocator);

	for (auto it = nodes[current_node].links.begin(); it != nodes[current_node].links.end(); ++it) {
		p_node_t next_node = it->second;
		rapidjson::Value subtree_value(rapidjson::kObjectType);
		to_json(next_node, subtree_value, allocator);
		stat_value.AddMember(actions_set.get_action_name(get_node_action_code(next_node)).c_str(), subtree_value, allocator);
	}
	return stat_value;
}

time_stats_tree_t::p_node_t time_stats_tree_t::new_node(int action_code) {
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

void time_stats_tree_t::substract_from(time_stats_tree_t::p_node_t lhs_node, time_stats_tree_t::p_node_t rhs_node, time_stats_tree_t &rhs_tree) const {
	rhs_tree.set_node_time(rhs_node, rhs_tree.get_node_time(rhs_node) - get_node_time(lhs_node));

	for (auto it = nodes[lhs_node].links.begin(); it != nodes[lhs_node].links.end(); ++it) {
		int action_code = it->first;
		p_node_t lhs_next_node = it->second;
		if (!rhs_tree.node_has_link(rhs_node, action_code)) {
			rhs_tree.add_new_link(rhs_node, action_code);
		}
		p_node_t rhs_next_node = rhs_tree.get_node_link(rhs_node, action_code);
		substract_from(lhs_next_node, rhs_next_node, rhs_tree);
	}
}

time_stats_updater_t::time_stats_updater_t(const size_t max_depth):
	current_node(0), time_stats_tree(nullptr), depth(0), max_depth(max_depth) {
	measurements.emplace(std::chrono::system_clock::now(), NULL);
}

time_stats_updater_t::time_stats_updater_t(concurrent_time_stats_tree_t &time_stats_tree, const size_t max_depth): max_depth(max_depth) {
	set_time_stats_tree(time_stats_tree);
	measurements.emplace(std::chrono::system_clock::now(), NULL);
}

time_stats_updater_t::~time_stats_updater_t() {
	if (depth != 0) {
		std::cerr << "~time_stats_updater(): extra measurements" << std::endl;
	}
	std::lock_guard<concurrent_time_stats_tree_t> guard(*time_stats_tree);

	while (!measurements.empty()) {
		pop_measurement();
	}
}

void time_stats_updater_t::set_time_stats_tree(concurrent_time_stats_tree_t &time_stats_tree) {
	current_node = time_stats_tree.get_time_stats_tree().root;
	this->time_stats_tree = &time_stats_tree;
	depth = 0;
}

bool time_stats_updater_t::has_time_stats_tree() const {
	return (time_stats_tree != nullptr);
}

void time_stats_updater_t::start(const int action_code) {
	start(action_code, std::chrono::system_clock::now());
}

void time_stats_updater_t::start(const int action_code, const time_stats_updater_t::time_point_t& start_time) {
	++depth;
	if (get_depth() > max_depth) {
		return;
	}

	time_stats_tree->lock();
	p_node_t next_node = time_stats_tree->get_time_stats_tree().add_new_link_if_missing(current_node, action_code);
	time_stats_tree->unlock();

	measurements.emplace(start_time, current_node);
	current_node = next_node;
}

void time_stats_updater_t::stop(const int action_code) {
	if (get_depth() > max_depth) {
		--depth;
		return;
	}

	std::lock_guard<concurrent_time_stats_tree_t> guard(*time_stats_tree);

	if (time_stats_tree->get_time_stats_tree().get_node_action_code(current_node) != action_code) {
		throw std::logic_error("Stopping wrong action");
	}
	pop_measurement();
}

void time_stats_updater_t::set_max_depth(const size_t max_depth) {
	if (depth != 0) {
		throw std::logic_error("can't change max_depth during update");
	}

	this->max_depth = max_depth;
}

size_t time_stats_updater_t::get_depth() const {
	return depth;
}

void time_stats_updater_t::pop_measurement(const time_point_t& end_time) {
	measurement previous_measurement = measurements.top();
	measurements.pop();
	time_stats_tree->get_time_stats_tree().inc_node_time(current_node, delta(previous_measurement.start_time, end_time));
	current_node = previous_measurement.previous_node;
	--depth;
}

action_guard::action_guard(time_stats_updater_t *updater, const int action_code):
	updater(updater), action_code(action_code), is_stopped(false) {
	updater->start(action_code);
}

action_guard::~action_guard() {
	if (!is_stopped) {
		updater->stop(action_code);
	}
}

void action_guard::stop() {
	if (is_stopped) {
		throw std::logic_error("action is already stopped");
	}

	updater->stop(action_code);
	is_stopped = true;
}

concurrent_time_stats_tree_t::concurrent_time_stats_tree_t(actions_set_t &actions_set): time_stats_tree(actions_set) {
}

void concurrent_time_stats_tree_t::lock() {
	tree_mutex.lock();
}

void concurrent_time_stats_tree_t::unlock() {
	tree_mutex.unlock();
}

time_stats_tree_t &concurrent_time_stats_tree_t::get_time_stats_tree() {
	return time_stats_tree;
}

}}
