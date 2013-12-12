/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
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

#ifndef ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP

#include "elliptics_id.h"
#include "elliptics_time.h"

namespace ioremap { namespace elliptics { namespace python {

struct elliptics_io_attr: public dnet_io_attr {
	elliptics_io_attr();
	elliptics_io_attr(const dnet_io_attr &io);
	elliptics_id parent;
	elliptics_id id;
	elliptics_time time;
};

void init_elliptics_io_attr();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP
