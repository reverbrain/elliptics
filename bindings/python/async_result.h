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

#ifndef ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP
#define ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP

#include <boost/python/list.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <boost/python/str.hpp>
#include <boost/python/errors.hpp>

#include <elliptics/result_entry.hpp>

#include "elliptics_time.h"
#include "gil_guard.h"
#include "py_converters.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

template <typename T>
struct callback_handlers {
	callback_handlers(PyObject *result, PyObject *final = NULL)
	: result_handler(result)
	, final_handler(final)
	{}

	void on_result(const T &result) {
		gil_guard gstate;
		try {
			bp::call<void>(result_handler, result);
		} catch (const bp::error_already_set& e) {}
	}

	void on_results(const std::vector<T> &results, const error_info &err) {
		gil_guard gstate;
		try {
			bp::call<void>(result_handler, convert_to_list(results), error(err.code(), err.message()));
		} catch (const bp::error_already_set& e) {}
	}

	void on_final(const error_info &err) {
		gil_guard gstate;
		try {
			bp::call<void>(final_handler, error(err.code(), err.message()));
		} catch (const bp::error_already_set& e) {}
	}

	PyObject *result_handler;
	PyObject *final_handler;
};

template <typename T>
struct python_async_result
{
	typedef typename async_result<T>::iterator iterator;

	std::shared_ptr<async_result<T>> scope;

	iterator begin() {
		return scope->begin();
	}

	iterator end() {
		return scope->end();
	}

	bp::list get() {
		return convert_to_list(scope->get());
	}

	void wait() {
		scope->wait();
	}

	bool successful() {
		if (!scope->ready()) {
			PyErr_SetString(PyExc_ValueError, "Async write operation hasn't yet been completed");
			bp::throw_error_already_set();
		}

		return !scope->error();
	}

	bool ready() {
		return scope->ready();
	}

	elliptics_time elapsed_time() {
		return elliptics_time(scope->elapsed_time());
	}

	void connect(bp::api::object &result_handler, bp::api::object &final_handler) {
		auto callback = boost::make_shared<callback_handlers<T>>(result_handler.ptr(), final_handler.ptr());
		scope->connect(boost::bind(&callback_handlers<T>::on_result, callback, _1),
		               boost::bind(&callback_handlers<T>::on_final, callback, _1));
	}

	void connect_all(bp::api::object &handler) {
		auto callback = boost::make_shared<callback_handlers<T>>(handler.ptr());
		scope->connect(boost::bind(&callback_handlers<T>::on_results, callback, _1, _2));
	}
};

template <typename T>
python_async_result<T> create_result(async_result<T> &&result)
{
	python_async_result<T> pyresult = { std::make_shared<async_result<T>>(std::move(result)) };
	return pyresult;
}

typedef python_async_result<iterator_result_entry>		python_iterator_result;
typedef python_async_result<read_result_entry> 			python_read_result;
typedef python_async_result<lookup_result_entry>		python_lookup_result;
typedef python_async_result<write_result_entry>			python_write_result;
typedef python_async_result<remove_result_entry>		python_remove_result;
typedef python_async_result<exec_result_entry>			python_exec_result;

typedef python_async_result<callback_result_entry>		python_async_set_indexes_result;
typedef python_async_result<find_indexes_result_entry>	python_find_indexes_result;
typedef python_async_result<index_entry>				python_check_indexes_result;

typedef python_async_result<stat_result_entry>			python_stat_result;
typedef python_async_result<stat_count_result_entry>	python_stat_count_result;

void init_async_results();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP
