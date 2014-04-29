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

#ifndef ELLIPTICS_REACT_HPP
#define ELLIPTICS_REACT_HPP

#include <mutex>
#include <memory>

#include <react/react.hpp>

#include "elliptics_react.h"

const size_t MAX_RECENT_LIST_SIZE = 1000;

namespace react {

class elliptics_react_aggregator_t : public aggregator_t {
public:
	elliptics_react_aggregator_t();
	~elliptics_react_aggregator_t();

	void aggregate(const call_tree_t &call_tree);
	void to_json(rapidjson::Value &value, rapidjson::Document::AllocatorType &allocator) const;

	std::list<call_tree_t> recent_call_trees;
	mutable std::mutex mutex;
};

} // namespace react

#endif // ELLIPTICS_REACT_HPP
