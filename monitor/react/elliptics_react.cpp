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

#include <react/aggregator.hpp>

namespace react {

elliptics_react_aggregator_t::elliptics_react_aggregator_t() {}

elliptics_react_aggregator_t::~elliptics_react_aggregator_t() {}

void elliptics_react_aggregator_t::aggregate(const call_tree_t &call_tree) {
	std::lock_guard<std::mutex> guard(mutex);
	recent_call_trees.push_back(call_tree);
	if (recent_call_trees.size() > MAX_RECENT_LIST_SIZE) {
		recent_call_trees.pop_front();
	}
}

} // namespace react
