#include "async_result.h"

#include <boost/python.hpp>

namespace ioremap { namespace elliptics { namespace python {

template <typename... Args>
struct def_async_result;

template <typename T>
struct def_async_result<T>
{
	static void init() {
		bp::class_<python_async_result<T>>("AsyncResult", bp::no_init)
			.def("__iter__", bp::iterator<python_async_result<T>>())
			.def("get", &python_async_result<T>::get)
			.def("wait", &python_async_result<T>::wait)
			.def("successful", &python_async_result<T>::successful)
			.def("ready", &python_async_result<T>::ready)
			.def("elapsed_time", &python_async_result<T>::elapsed_time)
			.def("connect", &python_async_result<T>::connect,
			     (bp::arg("result_handler"), bp::arg("final_handler")))
			.def("connect", &python_async_result<T>::connect_all,
			     (bp::arg("handler")))
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
						stat_result_entry,
						stat_count_result_entry,
						iterator_result_entry,
						exec_result_entry,
						find_indexes_result_entry,
						index_entry
					>::init();

}

} } } // namespace ioremap::elliptics::python
