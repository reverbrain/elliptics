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
					*reinterpret_cast<react::concurrent_call_tree_t*> (call_tree)
				);
	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return -EFAULT;
	}

	return 0;
}

namespace react {

elliptics_react_manager_t::elliptics_react_manager_t(): last_call_tree() {
}

void elliptics_react_manager_t::add_tree(concurrent_call_tree_t &call_tree) {
	std::lock_guard<std::mutex> guard(mutex);
	last_call_tree = std::make_shared<call_tree_t>(call_tree.copy_call_tree());
}

std::shared_ptr<call_tree_t> elliptics_react_manager_t::get_last_call_tree() const {
	std::lock_guard<std::mutex> guard(mutex);
	return last_call_tree;
}

} // namespace react
