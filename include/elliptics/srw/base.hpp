#ifndef __ELLIPTICS_SRW_BASE_HPP
#define __ELLIPTICS_SRW_BASE_HPP

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sstream>

#include <boost/thread/mutex.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/condition.hpp>

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif

namespace ioremap {
namespace srw {

#define SRW_TYPE_PYTHON		0
#define SRW_TYPE_SHARED		1

struct sph {
	uint64_t		size, binary_size;
	uint64_t		flags;
	int			pad;
	int			status;
	char			data[0];
} __attribute__ ((packed));

}}

#endif
