#ifndef __ELLIPTICS_SRW_SHARED_HPP
#define __ELLIPTICS_SRW_SHARED_HPP

#include <dlfcn.h>

#include <fstream>
#include <string>

#include <elliptics/cppdef.h>
#include <elliptics/srw/pipe.hpp>

using namespace zbr;

namespace ioremap {
namespace srw {

struct event_handler_t {
	virtual std::string		handle(struct sph &, const std::string &) = 0;
};

typedef void (* shared_init_t)(class shared &sh);
typedef boost::shared_ptr<event_handler_t> sevent_handler_t;

class shared {
	public:
		shared(const std::string &log, const std::string &init_path, const std::string &config_path) :
		m_config(config_path),
       		m_log(log.c_str(), std::ios::app) {
			load_from_file(init_path);
		}

		std::string process_data(struct sph &header, const std::string &data) {
			std::string event = get_event(header, data.data());
			std::string ret;

			boost::lock_guard<boost::mutex> guard(m_handlers_lock);

			std::map<std::string, sevent_handler_t>::iterator it = m_handlers.find(event);

			const char *have_handler = (it == m_handlers.end()) ? "true" : "false";
			m_log << event << ": key: " << header.key <<
				", data-size: " << header.data_size <<
				", binary-size: " << header.binary_size <<
				", have-handler: " << have_handler <<
				std::endl;

			if (it == m_handlers.end()) {
				header.status = -ENOENT;
				header.event_size = header.data_size = header.binary_size = 0;
				ret.assign((char *)&header, sizeof(struct sph));
				return ret;
			}

			return it->second->handle(header, data);
		}

		void add_handler(const std::string &event, sevent_handler_t handler) {
			boost::lock_guard<boost::mutex> guard(m_handlers_lock);

			std::pair<std::map<std::string, sevent_handler_t>::iterator, bool>
				ret = m_handlers.insert(std::make_pair(event, handler));
			if (ret.second == false) {
				m_handlers.erase(ret.first);
				m_handlers.insert(std::make_pair(event, handler));
			}
		}

	private:
		std::string m_config;
		std::ofstream m_log;
		boost::mutex m_handlers_lock;
		std::map<std::string, sevent_handler_t> m_handlers;

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
