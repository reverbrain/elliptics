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

#include "async_result.h"

#include <boost/python.hpp>

namespace ioremap { namespace elliptics { namespace python {

template <typename... Args>
struct def_async_result;

template <typename T>
error get_async_result_error(const python_async_result<T> &async) {
	if (!async.scope->ready()) {
		PyErr_SetString(PyExc_ValueError, "Async write operation hasn't yet been completed");
		bp::throw_error_already_set();
	}
	auto err = async.scope->error();
	return error(err.code(), err.message());
}

template <typename T>
struct def_async_result<T>
{
	static void init() {
		bp::class_<python_async_result<T>>(
		        "AsyncResult", "Future for waiting/getting results from asynchronous execution of operation")
			.def("__iter__", bp::iterator<python_async_result<T>>(),
			     "x.__iter__() <==> iter(x)\n"
			     "    Allows iterates though the operation results.\n"
			     "    Iterating will be performed as data becomes available\n\n"
			     "    for result in async_result:\n"
			     "        print 'The operation result: {0}'\n"
			     "              .format(result)")
			.def("get", &python_async_result<T>::get,
			     "get()\n"
			     "    Performs waiting all operation results and returns it by list\n\n"
			     "    results = async_result.get()\n"
			     "    first_result = results[0]")
			.def("wait", &python_async_result<T>::wait,
			     "wait()\n"
			     "    Performs waiting all operation result\n\n"
			     "    async_result.wait()\n"
			     "    results = async_result.get()")
			.def("successful", &python_async_result<T>::successful,
			     "successful()\n"
			     "    Returns status - is the operation successful.\n"
			     "    Throws exception if the operation hasn't been completed.\n\n"
			     "    try:\n"
			     "        print 'Operation successes:', async_result.successful\n"
			     "    except:\n"
			     "        print 'Operation hasn't been completed'\n"
			     "        async_result.wait()\n"
			     "        print 'Operation successes:', async_result.successful")
			.def("ready", &python_async_result<T>::ready,
			     "ready()\n"
			     "    Returns status - is all operation results received\n\n"
			     "    if async_result.read():\n"
			     "        print 'The operation has been completed'\n"
			     "    else:\n"
			     "        print 'The operation hasn't been completed'")
			.def("start_time", &python_async_result<T>::start_time,
			     "start_time()\n"
			     "    Returns elliptics.Time - timestamp when AsyncResult was created\n\n"
			     "    time = async_result.start_time()\n"
			     "    print 'The operation was started at {0}'\n"
			     "          .format(time)")
			.def("end_time", &python_async_result<T>::end_time,
			     "end_time()\n"
			     "    Returns elliptics.Time - timestamp when AsyncResult was finished\n"
			     "    or elliptics.Time(-1, -1) if it hasn't been finished yet\n"
			     "    time = async_result.end_time()\n"
			     "    print 'The operation was finished at {0}'\n"
			     "          .format(time)")
			.def("elapsed_time", &python_async_result<T>::elapsed_time,
			     "elapsed_time()\n"
			     "    Returns elliptics.Time - time spended for operation execution\n\n"
			     "    async_result.wait()\n"
			     "    time = async_result.elapsed_time()\n"
			     "    print 'The operation tooks {0} seconds and {1} nanoseconds'\n"
			     "          .format(time.tsec, time.tnsec)")
			.def("connect", &python_async_result<T>::connect,
			     (bp::arg("result_handler"), bp::arg("final_handler")),
			     "connect(result_handler, final_handler)\n"
			     "    Sets callbacks:\n"
			     "        result_handler will be called on each result\n"
			     "        final_handler will be called once after all results\n\n"
			     "    def rhandler(result):\n"
			     "         print 'The operation result:', result\n"
			     "    def fhandler(error):\n"
			     "        if error.code == 0:\n"
			     "            print 'The operation successfully completed'\n"
			     "        else:\n"
			     "            print 'The operation failed: {0}'\n"
			     "                  .format(error)\n"
			     "    async_result.connect(rhandler, fhandler)")
			.def("connect", &python_async_result<T>::connect_all,
			     (bp::arg("handler")),
			     "connect(result_handler)\n"
			     "    Sets callback for all operation results\n\n"
			     "    def handler(results, error):\n"
			     "        if error.code != 0:\n"
			     "            print 'The operation failed: {0}'\n"
			     "                  .format(error)\n"
			     "        else:\n"
			     "            print 'The operation results: {0}'\n"
			     "                  .format(results)\n"
			     "    async_result.connect(handler)")
			.def("error", get_async_result_error<T>,
			     "error()\n"
			     "     Returns error information about operation failure\n"
			     "     Throws exception if the operation hasn't been completed\n\n"
			     "     error = async_result.error()\n"
			     "     if error.code != 0:\n"
			     "         print 'The operation failed: {0}'\n"
			     "               .format(error)\n"
			     "     else:\n"
			     "         print 'The operation results: {0}'\n"
			     "               .format(results)\n")
		;
	}
};

template <>
struct def_async_result<>
{
	static void init() {}
};

template <typename T, typename... Args>
struct def_async_result<T, Args...>
{
	static void init() {
		def_async_result<T>::init();
		def_async_result<Args...>::init();
	}
};

void init_async_results() {

	def_async_result<	callback_result_entry,
						lookup_result_entry,
						read_result_entry,
						monitor_stat_result_entry,
						iterator_result_entry,
						exec_result_entry,
						find_indexes_result_entry,
						index_entry,
						backend_status_result_entry
					>::init();

}

} } } // namespace ioremap::elliptics::python
