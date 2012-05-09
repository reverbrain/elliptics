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
			m_log(lpath.c_str(), std::ios_base::app), m_p(ppath, true) {
			m_s.reset(new S(lpath, init, config));
		}
		virtual ~worker() {
		}

		void process() {
			while (true) {
				std::string data, binary, ret;

				m_log << getpid() << ": worker: going to read new data" << std::endl;
				m_p.read(data, binary);
				m_log << getpid() << ": worker: read " << data.size() << " " << binary.size() << std::endl;
				try {
					ret = m_s->process_data(data, binary);
				} catch (const std::exception &e) {
					m_log << getpid() << ": worker: exception: " << e.what() << std::endl;
					m_p.write(-EINVAL);
					continue;
				}

				m_log << getpid() << ": worker: processing completed: " << ret.size() << " bytes" << std::endl;
				m_p.write(0, ret);
			}
		}

	private:
		std::ofstream m_log;
		pipe m_p;
		std::auto_ptr<S> m_s;

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
				std::ostringstream type_str;
				type_str << ctl->type;

				std::ostringstream pipe_path;
				pipe_path << pipe_base << "-" << getpid();

				err = execl(ctl->binary, ctl->binary, "-l", ctl->log, "-p", pipe_path.str().c_str(),
						"-i", ctl->init, "-t", type_str.str().c_str(), "-c", ctl->config, NULL);

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
			m_p = boost::shared_ptr<pipe>(new pipe(pipe_path.str(), false));
		}

		virtual ~spawn() {
			kill(m_pid, SIGTERM);
			wait(NULL);
		}

		boost::shared_ptr<pipe> m_p;
		int m_pid;
};

}}

#endif /* __ELLIPTICS_SRW_WORKER_HPP */
