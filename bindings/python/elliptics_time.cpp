#include "elliptics_time.h"

#include <boost/python.hpp>

#include <elliptics/interface.h>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_time::elliptics_time(uint64_t tsec, uint64_t tnsec) {
	m_time.tsec = tsec;
	m_time.tnsec = tnsec;
}

elliptics_time::elliptics_time(const dnet_time &timestamp) {
	m_time = timestamp;
}

int elliptics_time::cmp_raw(const dnet_time &other) const {
	return dnet_time_cmp(&m_time, &other);
}

int elliptics_time::cmp(const elliptics_time &other) const {
	return dnet_time_cmp(&m_time, &other.m_time);
}

void elliptics_time::set_tsec(uint64_t tsec) {
	m_time.tsec = tsec;
}

uint64_t elliptics_time::get_tsec() {
	return m_time.tsec;
}

void elliptics_time::set_tnsec(uint64_t tnsec) {
	m_time.tnsec = tnsec;
}
uint64_t elliptics_time::get_tnsec() {
	return m_time.tnsec;
}

struct time_pickle : bp::pickle_suite
{
	static bp::tuple getinitargs(const elliptics_time& time) {
		return getstate(time);
	}

	static bp::tuple getstate(const elliptics_time& time) {
		return bp::make_tuple(time.m_time.tsec, time.m_time.tnsec);
	}

	static void setstate(elliptics_time& time, bp::tuple state) {
		if (len(state) != 2) {
			PyErr_SetObject(PyExc_ValueError,
				("expected 2-item tuple in call to __setstate__; got %s"
					% state).ptr()
				);
			bp::throw_error_already_set();
		}

		time.m_time.tsec = bp::extract<uint64_t>(state[0]);
		time.m_time.tnsec = bp::extract<uint64_t>(state[1]);
	}
};

void init_elliptcs_time() {



	bp::class_<elliptics_time>("Time",
			bp::init<uint64_t, uint64_t>(bp::args("tsec", "tnsec")))
		.add_property("tsec", &elliptics_time::get_tsec,
		                      &elliptics_time::set_tsec)
		.add_property("tnsec", &elliptics_time::get_tnsec,
		                       &elliptics_time::set_tnsec)
		.def("__cmp__", &elliptics_time::cmp_raw)
		.def("__cmp__", &elliptics_time::cmp)
		.def_pickle(time_pickle())
	;
}

} } } // namespace ioremap::elliptics::python
