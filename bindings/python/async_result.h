#ifndef ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP
#define ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP

#include <boost/python/list.hpp>

#include <elliptics/result_entry.hpp>

#include "elliptics_time.h"

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

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
		bp::list ret;

		auto res = scope->get();
		for (auto it = res.begin(), end = res.end(); it != end; ++it) {
			ret.append(*it);
		}

		return ret;
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

typedef python_async_result<stat_count_result_entry>	python_stat_count_result;

void init_async_results();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ASYNC_RESULTS_HPP
