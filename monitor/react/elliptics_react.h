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

#ifndef ELLIPTICS_REACT_H
#define ELLIPTICS_REACT_H

#include <react/react.h>

#include "elliptics_react_actions.h"

Q_EXTERN_C int elliptics_react_merge_call_tree(struct react_call_tree_t *call_tree, void *elliptics_react_manager);

#endif // ELLIPTICS_REACT_H
