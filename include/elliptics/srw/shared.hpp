#ifndef __ELLIPTICS_SRW_SHARED_HPP
#define __ELLIPTICS_SRW_SHARED_HPP

#include <dlfcn.h>

#include <elliptics/cppdef.h>
#include <elliptics/srw/pipe.hpp>

using namespace zbr;

namespace ioremap {
namespace srw {

typedef void (* shared_init_t)(class shared &sh);

class shared {
	public:
		shared(const std::string &, const std::string &init_path, const std::string &config_path) : m_config(config_path) {
			load_from_file(init_path);
		}

		std::string process_data(struct sph &, const std::string &) {
			return std::string();
		}

	private:
		std::string m_config;

		void load_from_file(const std::string &path) {
			void *handle;
			char *error;

			handle = dlopen(path.c_str(), RTLD_NOW);
			if (!handle) {
				std::ostringstream str;
				str << "Could not open shared library " << path << ": " << dlerror();
				throw std::runtime_error(str.str());
			}

			shared_init_t init = (shared_init_t)dlsym(handle, "init");

			if ((error = dlerror()) != NULL) {
				std::ostringstream str;
				str << "Could not get 'init' from shared library " << path << ": " << dlerror();

				dlclose(handle);
				throw std::runtime_error(str.str());
			}

			init(*this);
			dlclose(handle);
		}
};

}}

#endif /* __ELLIPTICS_SRW_SHARED_HPP */
