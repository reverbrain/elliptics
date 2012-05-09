#ifndef __ELLIPTICS_SRW_SHARED_HPP
#define __ELLIPTICS_SRW_SHARED_HPP

#include <dlfcn.h>

#include <elliptics/srw/pipe.hpp>

namespace ioremap {
namespace srw {

typedef void (* shared_init_t)(class shared &sh, const std::string &config);

class shared {
	public:
		shared(const std::string &log, const std::string &init_path, const std::string &config_path) :
			m_log(log.c_str(), std::ios_base::out | std::ios_base::app) {
				void *handle;
				char *error;

				handle = dlopen(init_path.c_str(), RTLD_NOW);
				if (!handle) {
					std::ostringstream str;
					str << "Could not open shared library " << init_path << ": " << dlerror();
					m_log << str.str() << std::endl;
					throw std::runtime_error(str.str());
				}

				shared_init_t init = (shared_init_t)dlsym(handle, "init");

				if ((error = dlerror()) != NULL) {
					std::ostringstream str;
					str << "Could not get 'init' from shared library " << init_path << ": " << dlerror();
					m_log << str.str() << std::endl;

					dlclose(handle);
					throw std::runtime_error(str.str());
				}

				dlclose(handle);

				init(*this, config_path);
		}

		std::string process_data(const std::string &data, const std::string &binary) {
			return data + binary;
		}
	private:
		std::ofstream m_log;
};

}}

#endif /* __ELLIPTICS_SRW_SHARED_HPP */
