#ifndef __SRW_HPP
#define __SRW_HPP

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <sstream>

#include <elliptics/srw/worker.hpp>

namespace ioremap {
namespace srw {

typedef boost::shared_ptr<spawn> shared_proc_t;
class pool {
	public:
		pool(struct srw_init_ctl *ctl) : m_log(ctl->log, std::ios::app) {
			for (int i = 0; i < ctl->num; ++i) {
				shared_proc_t sp(new spawn(ctl));

				boost::mutex::scoped_lock guard(m_lock);
				m_vec.push_back(sp);
			}

			/*
			 * std::fstream does not have filebuf with fd access anymore (at least with libstdc++ which comes with 3+ gcc)
			 * so we can not set O_CLOEXEC file like this
			 * 	fcntl(m_log.rdbuf()->fd(), F_GETFD, &flags);
			 * 	fcntl(m_log.rdbuf()->fd(), F_SETFD, flags | O_CLOEXEC);
			 * thus spawned workers will have a bunch of opened m_log files
			 */
		}

		virtual ~pool() {
		}

		void drop(int pid) {
			boost::mutex::scoped_lock guard(m_lock);
			shared_proc_t sp;

			for (std::vector<shared_proc_t>::iterator it = m_vec.begin(); it < m_vec.end(); ++it) {
				sp = *it;

				if (sp->m_pid == pid) {
					m_vec.erase(it);
					break;
				}
			}
		}

		std::string process(const std::string &data, const std::string &binary) {
			std::string ret;
			shared_proc_t sp;
			bool have_worker = false;

			m_log << getpid() << ": going to process new data" << std::endl;
			{
				boost::mutex::scoped_lock guard(m_lock);

				while (m_vec.empty()) {
					m_cond.wait(guard);
				}


				sp = m_vec.front();

				m_vec.erase(m_vec.begin());
				have_worker = true;
			}

			if (have_worker) {
				try {
					m_log << getpid() << ": writing new data: " << data.size() << " " << binary.size() << std::endl;
					sp->m_p->write(0, data, binary);

					m_log << getpid() << ": reading reply data" << std::endl;
					std::string tmp;
					sp->m_p->read(ret, tmp);
					m_log << getpid() << ": read reply data: " << ret.size() << " bytes" << std::endl;
				} catch (const std::exception &e) {
					m_log << getpid() << ": processing exception: " << e.what() << std::endl;

					boost::mutex::scoped_lock guard(m_lock);
					m_vec.push_back(sp);
					guard.unlock();

					m_cond.notify_one();

					throw;
				}

				boost::mutex::scoped_lock guard(m_lock);
				m_vec.push_back(sp);
				guard.unlock();

				m_cond.notify_one();
			}

			return ret;
		}

	private:
		std::ofstream m_log;
		boost::mutex m_lock;
		boost::condition m_cond;
		std::vector<shared_proc_t> m_vec;
};

} /* namespace srw */
} /* namespace ioremap */
#endif
