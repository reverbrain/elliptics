#ifndef ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP

#include "elliptics_id.h"
#include "elliptics_time.h"

namespace ioremap { namespace elliptics { namespace python {

struct elliptics_io_attr: public dnet_io_attr {
	elliptics_io_attr();
	elliptics_id parent;
	elliptics_id id;
	elliptics_time time;
};

void init_elliptcs_io_attr();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_IO_ATTR_HPP
