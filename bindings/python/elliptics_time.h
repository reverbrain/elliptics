#ifndef ELLIPTICS_PYTHON_ELLIPTICS_TIME_HPP
#define ELLIPTICS_PYTHON_ELLIPTICS_TIME_HPP

#include <elliptics/packet.h>

namespace ioremap { namespace elliptics { namespace python {

struct elliptics_time {
	elliptics_time(uint64_t tsec = 0, uint64_t tnsec = 0);

	elliptics_time(const dnet_time &timestamp);

	int cmp_raw(const dnet_time &other) const;

	int cmp(const elliptics_time &other) const;

	void set_tsec(uint64_t tsec);
	uint64_t get_tsec();

	void set_tnsec(uint64_t tnsec);
	uint64_t get_tnsec();

	dnet_time m_time;
};

void init_elliptcs_time();

} } } // namespace ioremap::elliptics::python

#endif // ELLIPTICS_PYTHON_ELLIPTICS_TIME_HPP
