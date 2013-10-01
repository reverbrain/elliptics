#include "elliptics_io_attr.h"

#include <boost/python.hpp>

namespace bp = boost::python;

namespace ioremap { namespace elliptics { namespace python {

elliptics_io_attr::elliptics_io_attr()
{
	start		= 0;
	num			= 0;
	user_flags	= 0;
	flags		= 0;
	offset		= 0;
	size		= 0;
}

void init_elliptcs_io_attr() {
	bp::class_<elliptics_io_attr>("IoAttr")
		.def_readwrite("parent", &elliptics_io_attr::parent)
		.def_readwrite("id", &elliptics_io_attr::id)
		.def_readwrite("time", &elliptics_io_attr::time)
		.def_readwrite("start", &dnet_io_attr::start)
		.def_readwrite("num", &dnet_io_attr::num)
		.def_readwrite("user_flags", &dnet_io_attr::user_flags)
		.def_readwrite("flags", &dnet_io_attr::flags)
		.def_readwrite("offset", &dnet_io_attr::offset)
		.def_readwrite("size", &dnet_io_attr::size)
	;
}

} } } // namespace ioremap::elliptics::python
