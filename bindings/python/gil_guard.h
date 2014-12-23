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

#ifndef ELLIPTICS_PYTHON_GIL_GUARD_HPP
#define ELLIPTICS_PYTHON_GIL_GUARD_HPP

namespace ioremap { namespace elliptics { namespace python {

struct gil_guard {
	gil_guard() {
		gstate = PyGILState_Ensure();
	}

	~gil_guard() {
		PyGILState_Release(gstate);
	}

	PyGILState_STATE gstate;
};

class py_allow_threads_scoped
{
public:
	py_allow_threads_scoped()
	: save(PyEval_SaveThread())
	{}

	void disallow()
	{
		PyEval_RestoreThread(save);
		save = NULL;
	}

	~py_allow_threads_scoped()
	{
		if (save)
			PyEval_RestoreThread(save);
	}
private:
	PyThreadState* save;
};

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_GIL_GUARD_HPP
