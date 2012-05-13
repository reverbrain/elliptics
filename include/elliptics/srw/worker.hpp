#ifndef __ELLIPTICS_SRW_WORKER_HPP
#define __ELLIPTICS_SRW_WORKER_HPP

#include <elliptics/srw/pipe.hpp>
#include <elliptics/srw/python.hpp>
#include <elliptics/srw/shared.hpp>

namespace ioremap {
namespace srw {

template <class S>
class worker {
	public:
		worker(const std::string &lpath, const std::string &ppath, const std::string &init, const std::string &config) :
		m_log(lpath.c_str(), std::ios_base::app),
		m_p(ppath, true),
       		m_s(lpath, init, config) {
		}
		virtual ~worker() {
		}

		void process() {
			while (true) {
				struct sph header;
				std::string data, ret;
				char *ret_data = NULL;

				memset(&header, 0, sizeof(struct sph));

				try {
					m_p.read(header, data);

					m_log << getpid() << ": worker: processing started: data-size: " << header.data_size <<
						", binary-size: " << header.binary_size <<
						", status: " << header.status << std::endl;

					ret = m_s.process_data(header, data);
					header.data_size = ret.size();
					header.binary_size = 0;
					header.status = 0;

					if (ret.size())
						ret_data = (char *)ret.data();
				} catch (const std::exception &e) {
					m_log << getpid() << ": worker: exception: " << e.what() << std::endl;
					if (header.status == 0)
						header.status = -EINVAL;
					header.data_size = header.binary_size = 0;
				}

				m_log << getpid() << ": worker: processing completed: data-size: " << header.data_size <<
					", status: " << header.status << ", data: " << ret_data << std::endl;

				m_p.write(header, ret_data);
			}
		}

	private:
		std::ofstream m_log;
		pipe m_p;
		S m_s;
};

class spawn {
	public:
		spawn(struct srw_init_ctl *ctl) {
			int err;

			std::string pipe_base = ctl->pipe;

			std::string pstr = pipe_base + ".w2c";
			unlink(pstr.c_str());

			pstr = pipe_base + ".c2w";
			unlink(pstr.c_str());

			m_pid = fork();
			if (m_pid < 0) {
				err = -errno;
				std::ostringstream str;

				str << "can not fork: " << err;
				throw std::runtime_error(str.str());
			}

			if (m_pid == 0) {
				std::ostringstream pipe_path;
				pipe_path << pipe_base << "-" << getpid();

				err = execl(ctl->binary, ctl->binary, "-l", ctl->log, "-p", pipe_path.str().c_str(),
						"-i", ctl->init, "-c", ctl->config, NULL);

				std::ofstream l(ctl->log, std::ios::app);
				err = -errno;
				l << getpid() << ": execl() returned " << err;
				exit(err);
			}

			int status;
			err = waitpid(m_pid, &status, WNOHANG);

			if (err < 0) {
				err = -errno;
				std::ostringstream str;
				str << getpid() << ": failed to waitpid: " << strerror(-err) << " : " << err;
				throw std::runtime_error(str.str());
			}

			if (err > 0 && WIFEXITED(status)) {
				err = WEXITSTATUS(status);

				std::ostringstream str;
				str << "Pid " << m_pid << " exited: " << strerror(-err) << " : " << err;
				throw std::runtime_error(str.str());
			}

			std::ostringstream pipe_path;
			pipe_path << pipe_base << "-" << m_pid;
			m_p.reset(new pipe(pipe_path.str(), false));
		}

		virtual ~spawn() {
			kill(m_pid, SIGTERM);
			wait(NULL);
		}

		std::string process(struct sph &header, const char *data) {
			boost::lock_guard<boost::mutex> guard(m_lock);

			m_p->write(header, data);
			std::string ret;
			m_p->read(header, ret);

			return ret;
		}

		int pid() const {
			return m_pid;
		}

	private:
		boost::mutex m_lock;
		std::auto_ptr<pipe> m_p;
		int m_pid;
};

}}

#endif /* __ELLIPTICS_SRW_WORKER_HPP */
