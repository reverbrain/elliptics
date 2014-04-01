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

#include "elliptics_react.hpp"

int elliptics_react_merge_call_tree(react_call_tree_t *call_tree, void *elliptics_react_manager) {
	if (!elliptics_react_manager) {
		return 0;
	}

	try {
		reinterpret_cast<react::elliptics_react_manager_t*> (elliptics_react_manager)->add_tree(
					*reinterpret_cast<react::concurrent_call_tree*> (call_tree)
				);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EFAULT;
	}

	return 0;
}

namespace react {

elliptics_react_manager_t::elliptics_react_manager_t():
	total_call_tree(get_actions_set()), last_call_tree(get_actions_set()) {
}

void elliptics_react_manager_t::add_tree(concurrent_call_tree &call_tree) {
	mutex.lock();
	auto call_tree_copy = call_tree.copy_time_stats_tree();
	call_tree_copy.merge_into(total_call_tree);
	last_call_tree.set(call_tree_copy);
	mutex.unlock();
}

const unordered_call_tree_t &elliptics_react_manager_t::get_total_call_tree() const {
	return total_call_tree;
}

const call_tree_t &elliptics_react_manager_t::get_last_call_tree() const {
	return last_call_tree;
}

} // namespace react
