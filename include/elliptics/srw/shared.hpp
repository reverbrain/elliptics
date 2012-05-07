#ifndef __ELLIPTICS_SRW_SHARED_HPP
#define __ELLIPTICS_SRW_SHARED_HPP

#include <elliptics/srw/base.hpp>

namespace ioremap {
namespace srw {

class shared {
	public:
		shared(const std::string &log, const std::string &, const std::string &) :
			m_log(log.c_str(), std::ios_base::out | std::ios_base::app) {
		}
		std::string process_data(const std::string &data, const std::string &binary) {
			return data + binary;
		}
	private:
		std::ofstream m_log;
};

}}

#endif /* __ELLIPTICS_SRW_SHARED_HPP */
