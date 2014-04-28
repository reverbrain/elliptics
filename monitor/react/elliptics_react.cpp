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

#include <react/aggregators/category_filter_aggregator.hpp>
#include <react/aggregators/complex_aggregator.hpp>
#include <react/aggregators/recent_trees_aggregator.hpp>

const size_t INCOMPLETE_TREES_LIST_SIZE = 100;
const size_t COMPLETE_TREES_LIST_SIZE = 100;

namespace react {

elliptics_react_aggregator_t::elliptics_react_aggregator_t(const actions_set_t &actions_set):
	aggregator_t(actions_set) {
	auto category_filter_aggregator = std::make_shared<category_filter_aggregator_t<bool>>(
		actions_set, std::make_shared<react::stat_extractor_t<bool>>("complete")
	);

	auto incomplete_trees_aggregator = std::make_shared<complex_aggregator_t>(actions_set);
	incomplete_trees_aggregator->add_aggregator(
		std::make_shared<recent_trees_aggregator_t>(actions_set, INCOMPLETE_TREES_LIST_SIZE)
	);
	category_filter_aggregator->add_category_aggregator(false, incomplete_trees_aggregator);

	auto complete_trees_aggregator = std::make_shared<complex_aggregator_t>(actions_set);
	complete_trees_aggregator->add_aggregator(
		std::make_shared<recent_trees_aggregator_t>(actions_set, COMPLETE_TREES_LIST_SIZE)
	);
	category_filter_aggregator->add_category_aggregator(true, complete_trees_aggregator);

	configurable_aggregator = category_filter_aggregator;
}

elliptics_react_aggregator_t::~elliptics_react_aggregator_t() {}

void elliptics_react_aggregator_t::aggregate(const call_tree_t &call_tree) {
	std::lock_guard<std::mutex> guard(mutex);
	configurable_aggregator->aggregate(call_tree);
}

void elliptics_react_aggregator_t::to_json(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) const {
	std::lock_guard<std::mutex> guard(mutex);
	configurable_aggregator->to_json(value, allocator);
}

} // namespace react
