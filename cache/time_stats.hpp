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
 * \brief List of possible actions in call tree
 */
enum actions {
	ACTION,
	ACTION_CACHE,
	ACTION_WRITE,
	ACTION_READ,
	ACTION_REMOVE,
	ACTION_LOOKUP,
	ACTION_LOCK,
	ACTION_FIND,
	ACTION_ADD_TO_PAGE,
	ACTION_RESIZE_PAGE,
	ACTION_SYNC_AFTER_APPEND,
	ACTION_WRITE_APPEND_ONLY,
	ACTION_WRITE_AFTER_APPEND_ONLY,
	ACTION_POPULATE_FROM_DISK,
	ACTION_CLEAR,
	ACTION_LIFECHECK,
	ACTION_CREATE_DATA,
	ACTION_CAS,
	ACTION_MODIFY,
	ACTION_DECREASE_KEY,
	ACTION_MOVE_RECORD,
	ACTION_ERASE,
	ACTION_REMOVE_LOCAL,
	ACTION_LOCAL_LOOKUP,
	ACTION_INIT,
	ACTION_LOCAL_READ,
	ACTION_PREPARE,
	ACTION_LOCAL_WRITE,
	ACTION_PREPARE_SYNC,
	ACTION_SYNC,
	ACTION_SYNC_BEFORE_OPERATION,
};

/*!
 * \brief Stores call tree with consumed times for each node.
 */
class time_stats_tree_t {
public:
	/*!
	 * \brief Constructor: initializes call tree with single root node
	 */
	time_stats_tree_t();

	/*!
	 * \brief Destructor: frees memory consumed by call tree
	 */
	~time_stats_tree_t();

	/*!
	 * \brief Converts call tree to json
	 * \param stat_value
	 * \param allocator
	 * \return
	 */
	rapidjson::Value& to_json(rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator) const;

	struct node_t;
	typedef size_t p_node_t;

	/*!
	 * \brief Struct that stores single node with it's action and time
	 */
	struct node_t {
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
	 * \param Target node
	 * \return
	 */
	int get_node_action_code(p_node_t node) const;

	/*!
	 * \brief Sets time for \a node
	 * \param Target node
	 * \param Time to set
	 */
	void set_node_time(p_node_t node, long long time);

	/*!
	 * \brief Returns time for \a node
	 * \param Target node
	 * \return
	 */
	long long int get_node_time(p_node_t node) const;

	/*!
	 * \brief Checks whether node has child with \a action_code
	 * \param Target node
	 * \param Child's action code
	 * \return
	 */
	bool node_has_link(p_node_t node, int action_code) const;

	/*!
	 * \brief Gets node's child with \a action_code
	 * \param Target node
	 * \param Child's action code
	 * \return
	 */
	p_node_t get_node_link(p_node_t node, int action_code) const;

	/*!
	 * \brief Adds new child to \a node with \a action_code
	 * \param Target node
	 * \param Child's action code
	 */
	void add_new_link(p_node_t node, int action_code);

	/*!
	 * \brief Merges this tree into \a another_tree
	 * \param Target tree
	 */
	void merge_into(time_stats_tree_t& another_tree) const;

	/*!
	 * \brief Root of the tree
	 */
	p_node_t root;

	/*!
	 * \brief Lock to handle concurrency during updates
	 */
	mutable std::mutex lock;

private:
	/*!
	 * \internal
	 *
	 * \brief Recursively converts subtree to json
	 * \param current_node
	 * \param stat_value
	 * \param allocator
	 * \return
	 */
	rapidjson::Value& to_json(p_node_t current_node, rapidjson::Value &stat_value,
							  rapidjson::Document::AllocatorType &allocator) const;

	/*!
	 * \internal
	 *
	 * \brief Allocates space for new node
	 * \param action_code
	 * \return
	 */
	p_node_t new_node(int action_code);

	/*!
	 * \internal
	 *
	 * \brief Recursively merges \a lhd_node into \a rhs_node
	 * \param lhs_node
	 * \param rhs_node
	 * \param rhs_tree
	 */
	void merge_into(p_node_t lhs_node, p_node_t rhs_node, time_stats_tree_t& rhs_tree) const;

	/*!
	 * \brief Tree nodes
	 */
	std::vector<node_t> nodes;
};

/*!
 * \brief Class for interactive building of call tree
 *
 *  Allows you to log actions in call-tree manner.
 */
class time_stats_updater_t {
public:
	typedef time_stats_tree_t::node_t node_t;
	typedef time_stats_tree_t::p_node_t p_node_t;
	typedef std::chrono::time_point<std::chrono::system_clock> time_point_t;

	/*!
	 * \brief Constructor: Initializes updater without target tree
	 * \param Maximum depth of call stack
	 */
	time_stats_updater_t(const size_t max_depth = 1);

	/*!
	 * \brief Constructor: Initializes updater with target tree
	 * \param Target tree
	 * \param Maximum depth of call stack
	 */
	time_stats_updater_t(time_stats_tree_t &t, const size_t max_depth = 1);

	/*!
	 * \brief Destructor: Checks if all actions are were correctly finished.
	 */
	~time_stats_updater_t();

	/*!
	 * \brief Sets target tree for updates
	 * \param Target tree
	 */
	void set_time_stats_tree(time_stats_tree_t &t);

	/*!
	 * \brief Checks whether tree for updates is set
	 * \return
	 */
	bool has_time_stats_tree() const;

	/*!
	 * \brief Starts new branch in tree with action \a action_code
	 * \param action_code
	 */
	void start(const int action_code);

	/*!
	 * \brief Starts new branch in tree with action \a action_code and with specified start time
	 * \param action_code
	 * \param Action start time
	 */
	void start(const int action_code, const time_point_t& start_time);

	/*!
	 * \brief Stops last action. Updates total consumed time in call-tree.
	 * \param action_code
	 */
	void stop(const int action_code);

	/*!
	 * \brief Sets max call stack depth to \a max_depth
	 * \param max_depth
	 */
	void set_max_depth(const size_t max_depth);

	/*!
	 * \brief Gets current call stack depth
	 * \return
	 */
	size_t get_depth() const;

private:
	/*!
	 * \internal
	 *
	 * \brief Returns delta between two time_points
	 */
	template<class Period = std::chrono::microseconds>
	long long int delta(time_point_t& start, const time_point_t& end) const
	{
		return (std::chrono::duration_cast<Period> (end - start)).count();
	}

	/*!
	 * \brief Represents single call measurement
	 */
	struct measurement {
		/*!
		 * \brief Constructor: Initializes measurement with specified start time and pointer to previous node in call stack
		 * \param Start time
		 * \param Pointer to previous node in call stack
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
	 * \param End time of the measurement
	 */
	void pop_measurement(const time_point_t& end_time = std::chrono::system_clock::now());

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
	time_stats_tree_t* t;

	/*!
	 * \brief Current call stack depth
	 */
	size_t depth;

	/*!
	 * \brief Maximum monitored call stack depth
	 */
	size_t max_depth;
};

/*!
 * \brief Auxiliary class for logging actions with variable place of stop time (branching/end of function/end of scope)
 */
class action_guard {
public:
	/*!
	 * \brief Constructor: Initializes guard and starts action with \a action_code
	 * \param Updater whos start will is called
	 * \param action_code
	 */
	action_guard(time_stats_updater_t *updater, const int action_code);

	/*!
	 * \brief Destructor: Stops action if it is not already stopped
	 */
	~action_guard();

	/*!
	 * \brief Allowes to stop action manually
	 */
	void stop();

private:
	/*!
	 * \brief Updater whos start/stop are called
	 */
	time_stats_updater_t *updater;

	/*!
	 * \brief Action code for action
	 */
	const int action_code;

	/*!
	 * \brief Shows if the action is already stopped
	 */
	bool is_stopped;
};

}}

#endif // TIME_STATS_HPP
