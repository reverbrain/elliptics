/*
* 2013+ Copyright (c) Kirill Smorodinnikov <shaitkir@gmail.com>
* All rights reserved.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*/

#ifndef ELLIPTICS_PYTHON_GIL_GUARD_HPP
#define ELLIPTICS_PYTHON_GIL_GUARD_HPP

namespace ioremap { namespace elliptics { namespace python {

struct gil_guard {
	gil_guard() {
		if (!PyEval_ThreadsInitialized()) {
			PyEval_InitThreads();
			PyEval_ReleaseLock();
		}
		gstate = PyGILState_Ensure();
	}

	~gil_guard() {
		PyGILState_Release(gstate);
	}

	PyGILState_STATE gstate;
};

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_GIL_GUARD_HPP
