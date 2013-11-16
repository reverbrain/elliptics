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

#include "elliptics_io_attr.h"

#include <boost/python.hpp>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_io_attr::elliptics_io_attr()
{
	start		= 0;
	num			= 0;
	user_flags	= 0;
	flags		= 0;
	offset		= 0;
	size		= 0;
}

void init_elliptcs_io_attr() {
	bp::class_<elliptics_io_attr>("IoAttr")
		.def_readwrite("parent", &elliptics_io_attr::parent)
		.def_readwrite("id", &elliptics_io_attr::id)
		.def_readwrite("timestamp", &elliptics_io_attr::time)
		.def_readwrite("start", &dnet_io_attr::start)
		.def_readwrite("num", &dnet_io_attr::num)
		.def_readwrite("user_flags", &dnet_io_attr::user_flags)
		.def_readwrite("flags", &dnet_io_attr::flags)
		.def_readwrite("offset", &dnet_io_attr::offset)
		.def_readwrite("size", &dnet_io_attr::size)
	;
}

} } } // namespace ioremap::elliptics::python
