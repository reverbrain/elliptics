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
