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

class process_t {
	public:
		virtual void process(struct sph &header, const char *data) = 0;
};

typedef boost::shared_ptr<process_t> sprocess_t;

typedef boost::shared_ptr<spawn> shared_proc_t;
class pool {
	public:
		pool(struct srw_init_ctl *ctl) : m_log(ctl->log, std::ios::app) {
			for (int i = 0; i < ctl->num; ++i) {
				shared_proc_t sp(new spawn(ctl));

				m_workers.insert(std::make_pair(sp->pid(), sp));
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

			m_workers.erase(pid);
		}

		std::string process(struct sph &header, const char *data) {
			return select_worker(header, data);
		}

	private:
		std::ofstream m_log;
		boost::mutex m_lock;
		boost::condition m_cond;
		std::map<int, shared_proc_t> m_workers;
		std::map<std::string, std::vector<int> > m_process;

		std::string select_worker(struct sph &header, const char *data) {
			std::string event;
			event.assign(data, header.event_size);
			std::map<std::string, std::vector<int> >::iterator it = m_process.find(event);

			if (it == m_process.end()) {
				std::ostringstream str;
				str << event << ": could not find handler";
				header.status = -ENOENT;
				throw std::runtime_error(str.str());
			}

			std::vector<int> pids = it->second;

			return worker_process(pids, header, data);
		}

		std::string worker_process(std::vector<int> &pids, struct sph &header, const char *data) {
			int pid_pos = header.key % pids.size();
			int pid = pids[pid_pos];

			std::map<int, shared_proc_t>::iterator it = m_workers.find(pid);
			if (it == m_workers.end()) {
				std::string event;
				event.assign(data, header.event_size);

				std::ostringstream str;
				str << event << ": worker with pid (" << pid << ") is dead";
				header.status = -ENOENT;
				throw std::runtime_error(str.str());
			}

			return it->second->process(header, data);
		}
};

} /* namespace srw */
} /* namespace ioremap */
#endif
