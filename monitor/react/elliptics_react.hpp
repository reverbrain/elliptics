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

#include <react/react.hpp>

#include "elliptics_react.h"

namespace react {

typedef concurrent_call_tree_t<call_tree_t> concurrent_call_tree;

class elliptics_react_manager_t {
public:
	elliptics_react_manager_t();

	void add_tree(concurrent_call_tree &call_tree);
	const unordered_call_tree_t &get_total_call_tree() const;
	const call_tree_t &get_last_call_tree() const;
private:
	std::mutex mutex;
	unordered_call_tree_t total_call_tree;
	call_tree_t last_call_tree;
};

} // namespace react

#endif // ELLIPTICS_REACT_HPP
