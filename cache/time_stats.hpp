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

/*!
 * \file time_stats.hpp
 * \brief Tools for time monitoring
 *
 * This file contains tools for detailed time monitoring,
 * that allow you to gather time statistics in call tree manner.
 * This way you can see time consumed by each action and
 * it's distribution between other inner actions, which perfectly reveals bottlenecks.
 *
 * Example of simple monitoring:
 * \code
 *      actions_set_t actions_set; // Define set of actions that will be monitored
 *      const int ACTION_READ = actions_set.define_new_action("READ");
 *      ...
 *      const int ACTION_FIND = actions_set.define_new_action("FIND");
 *      concurrent_time_stats_tree_t time_stats(actions_set); // Call tree for storing statistics.
 *      time_stats_updater_t updater(time_stats); // Updater for gathering of statistics.
 *
 *      void cache_read(...) {
 *          action_guard(updater, ACTION_READ); // Creates new guard and starts action which will be stopped on guard's destructor
 *          updater.start(ACTION_FIND); // Starts new action which will be inner to ACTION_READ
 *          found = find_record(...);
 *          updater.stop(ACTION_FIND);
 *          if (!found) {
 *              action_guard(updater, ACTION_READ_FROM_DISK);
 *              updater.start(ACTION_LOAD_FROM_DISK);
 *              data = read_from_disk(...);
 *              updater.stop(ACTION_LOAD_FROM_DISK);
 *              updater.start(ACTION_PUT_INTO_CACHE);
 *              put_into_cache(...);
 *              updater.stop(ACTION_PUT_INTO_CACHE);
 *              return data; // Here all action guards are destructed and actions are correctly finished
 *          }
 *          updater.start(ACTION_LOAD_FROM_CACHE);
 *          data = load_from_cache(...);
 *          updater.stop(ACTION_LOAD_FROM_CACHE);
 *          return data;
 *      }
 * \endcode
 * This code with build such call tree:
 *
 * - ACTION_READ
 *      - ACTION_FIND
 *      - ACTION_READ_FROM_DISK
 *          - ACTION_LOAD_FROM_DISK
 *          - ACTION_PUT_INTO_CACHE
 *      - ACTION_LOAD_FROM_CACHE
 */

#ifndef TIME_STATS_HPP
#define TIME_STATS_HPP

#include <stack>
#include <chrono>
#include <unordered_map>
#include <map>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <mutex>

#include "../monitor/rapidjson/document.h"
#include "../monitor/rapidjson/writer.h"
#include "../monitor/rapidjson/stringbuffer.h"

namespace ioremap { namespace cache {

/*!
 * \brief Represents set of actions that allows defining new actions and resolving action's names by their codes
 */
class actions_set_t {
public:
	/*!
	 * \brief Initializes empty actions set
	 */
	actions_set_t() {}

	/*!
	 * \brief Frees memory consumed by actions set
	 */
	~actions_set_t() {}

	/*!
	 * \brief Defines new action
	 * \param action_name new action's name
	 * \return new action's code
	 */
	int define_new_action(const std::string& action_name) {
		int action_code = actions_names.size();
		actions_names.insert(make_pair(action_code, action_name));
		return action_code;
	}

	/*!
	 * \brief Gets action's name by it's \a action_code
	 * \param action_code
	 * \return action's name
	 */
	std::string get_action_name(int action_code) const {
		return actions_names.at(action_code);
	}

private:
	/*!
	 * \brief Map between action's codes and action's names
	 */
	std::unordered_map<int, std::string> actions_names;
};

/*!
 * \brief Stores call tree.
 *
 * Each node of the tree represents information about single action:
 * - Action code
 * - Total time consumed during this action
 */
class time_stats_tree_t {
public:
	/*!
	 * \brief initializes call tree with single root node and action set
	 * \param actions_set Set of available actions for monitoring in call tree
	 */
	time_stats_tree_t(const actions_set_t &actions_set): actions_set(actions_set) {
		root = new_node(-1);
	}

	/*!
	 * \brief frees memory consumed by call tree
	 */
	~time_stats_tree_t() {}

	/*!
	 * \brief Converts call tree to json
	 * \param stat_value Json node for writing
	 * \param allocator Json allocator
	 * \return Modified json node
	 */
	rapidjson::Value& to_json(rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator) const {
		return to_json(root, stat_value, allocator);
	}

	struct node_t;
	/*!
	 * \brief Pointer to node type
	 */
	typedef size_t p_node_t;

	/*!
	 * \brief Struct that stores single node that represents action in call tree.
	 *
	 * Action is characterized by it's code(name) and total time consumed by this action.
	 */
	struct node_t {
		/*!
		 * \brief Initializes node with \a action_code and zero consumed time
		 * \param action_code Action code of the node
		 */
		node_t(int action_code): action_code(action_code), time(0) {}

		/*!
		 * \brief action which this node represents
		 */
		int action_code;
		/*!
		 * \brief total time consumed in this node
		 */
		long long int time;

		/*!
		 * \brief Child nodes, actions that happen inside this action
		 */
		std::unordered_map<int, p_node_t> links;
	};

	/*!
	 * \brief Returns an action code for \a node
	 * \param node Target node
	 * \return Action code of the target node
	 */
	int get_node_action_code(p_node_t node) const {
		return nodes[node].action_code;
	}

	/*!
	 * \brief Sets total time consumed by action represented by \a node
	 * \param node Action's node
	 * \param time New time value
	 */
	void set_node_time(p_node_t node, long long time) {
		nodes[node].time = time;
	}

	/*!
	 * \brief Increments total time consumed by action represented by \a node
	 * \param node Action's node
	 * \param delta Value by which time will be incremented
	 */
	void inc_node_time(p_node_t node, long long delta) {
		nodes[node].time += delta;
	}

	/*!
	 * \brief Returns total time consumed by action represented by \a node
	 * \param node Action's node
	 * \return Time consumed by action
	 */
	long long int get_node_time(p_node_t node) const {
		return nodes[node].time;
	}

	/*!
	 * \brief Checks whether node has child with \a action_code
	 * \param node Target node
	 * \param action_code Child's action code
	 * \return whether \a node has child with \a action_code
	 */
	bool node_has_link(p_node_t node, int action_code) const {
		return nodes[node].links.find(action_code) != nodes[node].links.end();
	}

	/*!
	 * \brief Gets node's child with \a action_code
	 * \param node Target node
	 * \param action_code Child's action code
	 * \return Pointer to child with \a action_code
	 */
	p_node_t get_node_link(p_node_t node, int action_code) const {
		return nodes[node].links.at(action_code);
	}

	/*!
	 * \brief Adds new child to \a node with \a action_code
	 * \param node Target node
	 * \param action_code Child's action code
	 * \return Pointer to newly created child of \a node with \a action_code
	 */
	p_node_t add_new_link(p_node_t node, int action_code) {
		p_node_t action_node = new_node(action_code);
		nodes[node].links.insert(std::make_pair(action_code, action_node));
		return action_node;
	}

	/*!
	 * \brief Adds new child to \a node with \a action_code if it's missing
	 * \param node Target node
	 * \param action_code Child's action code
	 * \return Pointer to child of \a node with \a action_code
	 */
	p_node_t add_new_link_if_missing(p_node_t node, int action_code) {
		auto link = nodes[node].links.find(action_code);
		if (link == nodes[node].links.end()) {
			return add_new_link(node, action_code);
		}
		return link->second;
	}

	/*!
	 * \brief Merges this tree into \a another_tree
	 * \param another_tree Tree where current tree will be merged in
	 */
	void merge_into(time_stats_tree_t& another_tree) const {
		merge_into(root, another_tree.root, another_tree);
	}

	/*!
	 * \brief Calculates time differences between this tree and \a another tree
	 * \param another_tree Tree which will be substracted from this tree
	 */
	time_stats_tree_t diff_from(time_stats_tree_t& another_tree) const {
		time_stats_tree_t diff_tree = *this;
		another_tree.substract_from(diff_tree);
		return std::move(diff_tree);
	}

	/*!
	 * \brief Substracts time stats of this tree from \a another tree
	 * \param another_tree Tree from which this tree will be substracted
	 */
	void substract_from(time_stats_tree_t& another_tree) const {
		return substract_from(root, another_tree.root, another_tree);
	}

	/*!
	 * \brief Root of the call tree
	 */
	p_node_t root;

private:
	/*!
	 * \internal
	 *
	 * \brief Recursively converts subtree to json
	 * \param current_node Node which subtree will be converted
	 * \param stat_value Json node for writing
	 * \param allocator Json allocator
	 * \return Modified json node
	 */
	rapidjson::Value& to_json(p_node_t current_node, rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator) const {

		stat_value.AddMember("time", (int64_t) get_node_time(current_node), allocator);

		for (auto it = nodes[current_node].links.begin(); it != nodes[current_node].links.end(); ++it) {
			p_node_t next_node = it->second;
			rapidjson::Value subtree_value(rapidjson::kObjectType);
			to_json(next_node, subtree_value, allocator);
			stat_value.AddMember(actions_set.get_action_name(get_node_action_code(next_node)).c_str(), subtree_value, allocator);
		}
		return stat_value;
	}

	/*!
	 * \internal
	 *
	 * \brief Allocates space for new node
	 * \param action_code
	 * \return Pointer to newly created node
	 */
	p_node_t new_node(int action_code) {
		nodes.emplace_back(action_code);
		return nodes.size() - 1;
	}

	/*!
	 * \internal
	 *
	 * \brief Recursively merges \a lhs_node into \a rhs_node
	 * \param lhs_node Node which will be merged
	 * \param rhs_node
	 * \param rhs_tree
	 */
	void merge_into(p_node_t lhs_node, p_node_t rhs_node, time_stats_tree_t& rhs_tree) const {
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

	/*!
	 * \internal
	 *
	 * \brief Recursively substracts \a lhs_node from \a rhs_node
	 * \param lhs_node Node which will be substracted
	 * \param rhs_node
	 * \param rhs_tree
	 */
	void substract_from(p_node_t lhs_node, p_node_t rhs_node, time_stats_tree_t& rhs_tree) const {
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

	/*!
	 * \brief Tree nodes
	 */
	std::vector<node_t> nodes;

	/*!
	 * \brief Available actions for monitoring
	 */
	const actions_set_t& actions_set;
};

/*!
 * \brief Concurrent version of time stats tree to handle simultanious updates
 */
class concurrent_time_stats_tree_t {
public:
	/*!
	 * \brief Initializes time_stats_tree with \a actions_set
	 * \param actions_set Set of available action for monitoring
	 */
	concurrent_time_stats_tree_t(actions_set_t &actions_set): time_stats_tree(actions_set) {
	}

	/*!
	 * \brief Gets ownership of time stats tree
	 */
	void lock() {
		tree_mutex.lock();
	}

	/*!
	 * \brief Releases ownership of time stats tree
	 */
	void unlock() {
		tree_mutex.unlock();
	}

	/*!
	 * \brief Returns inner time stats tree
	 * \return Inner time stats tree
	 */
	time_stats_tree_t& get_time_stats_tree() {
		return time_stats_tree;
	}

private:
	/*!
	 * \brief Lock to handle concurrency during updates
	 */
	mutable std::mutex tree_mutex;

	/*!
	 * \brief Inner time_stats_tree
	 */
	time_stats_tree_t time_stats_tree;

};

/*!
 * \brief Class for interactive building of call tree
 *
 *  Allows you to log actions in call-tree manner.
 */
class time_stats_updater_t {
public:
	/*!
	 * \brief Call tree node type
	 */
	typedef time_stats_tree_t::node_t node_t;

	/*!
	 * \brief Pointer to call tree node type
	 */
	typedef time_stats_tree_t::p_node_t p_node_t;

	/*!
	 * \brief Time point type
	 */
	typedef std::chrono::time_point<std::chrono::system_clock> time_point_t;

	/*!
	 * \brief Initializes updater without target tree
	 * \param max_depth Maximum monitored depth of call stack
	 */
	time_stats_updater_t(const size_t max_depth = DEFAULT_DEPTH):
		current_node(0), time_stats_tree(NULL), depth(0), max_depth(max_depth) {
		measurements.emplace(std::chrono::system_clock::now(), NULL);
	}

	/*!
	 * \brief Initializes updater with target tree
	 * \param time_stats_tree Tree used to monitor updates
	 * \param max_depth Maximum monitored depth of call stack
	 */
	time_stats_updater_t(concurrent_time_stats_tree_t &time_stats_tree,
						 const size_t max_depth = DEFAULT_DEPTH): max_depth(max_depth) {
		set_time_stats_tree(time_stats_tree);
		measurements.emplace(std::chrono::system_clock::now(), NULL);
	}

	/*!
	 * \brief Checks if all actions were correctly finished.
	 */
	~time_stats_updater_t() {
		if (depth != 0) {
			std::cerr << "~time_stats_updater(): extra measurements" << std::endl;
		}
		std::lock_guard<concurrent_time_stats_tree_t> guard(*time_stats_tree);

		while (!measurements.empty()) {
			pop_measurement();
		}
	}

	/*!
	 * \brief Sets target tree for updates
	 * \param time_stats_tree Tree used to monitor updates
	 */
	void set_time_stats_tree(concurrent_time_stats_tree_t &time_stats_tree) {
		current_node = time_stats_tree.get_time_stats_tree().root;
		this->time_stats_tree = &time_stats_tree;
		depth = 0;
	}

	/*!
	 * \brief Checks whether tree for updates is set
	 * \return whether updater target tree was set
	 */
	bool has_time_stats_tree() const {
		return (time_stats_tree != NULL);
	}

	/*!
	 * \brief Starts new branch in tree with action \a action_code
	 * \param action_code Code of new action
	 */
	void start(const int action_code) {
		start(action_code, std::chrono::system_clock::now());
	}

	/*!
	 * \brief Starts new branch in tree with action \a action_code and with specified start time
	 * \param action_code Code of new action
	 * \param start_time Action start time
	 */
	void start(const int action_code, const time_point_t& start_time) {
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

	/*!
	 * \brief Stops last action. Updates total consumed time in call-tree.
	 * \param action_code Code of finished action
	 */
	void stop(const int action_code) {
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

	/*!
	 * \brief Sets max monitored call stack depth to \a max_depth
	 * \param max_depth Max monitored call stack depth
	 */
	void set_max_depth(const size_t max_depth) {
		if (depth != 0) {
			throw std::logic_error("can't change max_depth during update");
		}

		this->max_depth = max_depth;
	}

	/*!
	 * \brief Gets current call stack depth
	 * \return Current call stack depth
	 */
	size_t get_depth() const {
		return depth;
	}

private:
	/*!
	 * \internal
	 *
	 * \brief Returns delta between two time_points
	 */
	template<class Period = std::chrono::microseconds>
	long long int delta(time_point_t& start, const time_point_t& end) const {
		return (std::chrono::duration_cast<Period> (end - start)).count();
	}

	/*!
	 * \brief Represents single call measurement
	 */
	struct measurement {
		/*!
		 * \brief Initializes measurement with specified start time and pointer to previous node in call stack
		 * \param time Start time
		 * \param previous_node Pointer to previous node in call stack
		 */
		measurement(const time_point_t& time, p_node_t previous_node): start_time(time),
			previous_node(previous_node) {}

		/*!
		 * \brief Start time of the measurement
		 */
		time_point_t start_time;

		/*!
		 * \brief Pointer to previous node in call stack
		 */
		p_node_t previous_node;
	};

	/*!
	 * \brief Removes measurement from top of call stack and updates corresponding node in call-tree
	 * \param end_time End time of the measurement
	 */
	void pop_measurement(const time_point_t& end_time = std::chrono::system_clock::now()) {
		measurement previous_measurement = measurements.top();
		measurements.pop();
		time_stats_tree->get_time_stats_tree().inc_node_time(current_node, delta(previous_measurement.start_time, end_time));
		current_node = previous_measurement.previous_node;
		--depth;
	}

	/*!
	 * \brief Current position in call-tree
	 */
	p_node_t current_node;

	/*!
	 * \brief Call stack
	 */
	std::stack<measurement> measurements;

	/*!
	 * \brief Target call-tree
	 */
	concurrent_time_stats_tree_t* time_stats_tree;

	/*!
	 * \brief Current call stack depth
	 */
	size_t depth;

	/*!
	 * \brief Maximum monitored call stack depth
	 */
	size_t max_depth;

	/*!
	 * \brief Default monitored call stack depth
	 */
	static const size_t DEFAULT_DEPTH = -1;
};

/*!
 * \brief Auxiliary class for logging actions with variable place of stop time (branching/end of function/end of scope)
 */
class action_guard {
public:
	/*!
	 * \brief Initializes guard and starts action with \a action_code
	 * \param updater Updater whos start is called
	 * \param action_code Code of new action
	 */
	action_guard(time_stats_updater_t *updater, const int action_code):
		updater(updater), action_code(action_code), is_stopped(false) {
		updater->start(action_code);
	}

	/*!
	 * \brief Stops action if it is not already stopped
	 */
	~action_guard() {
		if (!is_stopped) {
			updater->stop(action_code);
		}
	}

	/*!
	 * \brief Allows to stop action manually
	 */
	void stop() {
		if (is_stopped) {
			throw std::logic_error("action is already stopped");
		}

		updater->stop(action_code);
		is_stopped = true;
	}

private:
	/*!
	 * \brief Updater whos start/stop are called
	 */
	time_stats_updater_t *updater;

	/*!
	 * \brief Action code of guarded action
	 */
	const int action_code;

	/*!
	 * \brief Shows if action is already stopped
	 */
	bool is_stopped;
};

}}

#endif // TIME_STATS_HPP
