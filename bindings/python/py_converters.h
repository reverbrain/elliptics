#ifndef ELLIPTICS_PYTHON_PY_CONVERTERS_HPP
#define ELLIPTICS_PYTHON_PY_CONVERTERS_HPP

#include <boost/python/list.hpp>
#include <boost/python/stl_iterator.hpp>
#include <boost/python/iterator.hpp>

#include <vector>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

template <typename T>
static std::vector<T> convert_to_vector(const bp::api::object &list)
{
	bp::stl_input_iterator<T> begin(list), end;
	return std::vector<T>(begin, end);
}

template <typename T>
static bp::list convert_to_list(const std::vector<T> &vect)
{
	bp::list ret;

	for (auto it = vect.cbegin(), end = vect.cend(); it != end; ++it) {
		ret.append(*it);
	}

	return ret;
}

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_PY_CONVERTERS_HPP
