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

std::string elliptics_time::to_str() const {
	std::string ret;
	ret += dnet_print_time(&m_time);
	return ret;
}

std::string elliptics_time::to_repr() const {
	std::string ret = "elliptics.Time(";
	ret += dnet_print_time(&m_time);
	ret += ")";
	return ret;
}

elliptics_time elliptics_time::now() {
	elliptics_time ret;
	dnet_current_time(&ret.m_time);
	return ret;
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

void init_elliptics_time() {

	bp::class_<elliptics_time>("Time",
			bp::init<uint64_t, uint64_t>(bp::args("tsec", "tnsec")))
		.add_property("tsec", &elliptics_time::get_tsec,
		                      &elliptics_time::set_tsec)
		.add_property("tnsec", &elliptics_time::get_tnsec,
		                       &elliptics_time::set_tnsec)
		.def("__cmp__", &elliptics_time::cmp_raw)
		.def("__cmp__", &elliptics_time::cmp)
		.def("__str__", &elliptics_time::to_str)
		.def("__repr__", &elliptics_time::to_repr)
		.def_pickle(time_pickle())
		.def("now", &elliptics_time::now)
		.staticmethod("now")
	;
}

} } } // namespace ioremap::elliptics::python
