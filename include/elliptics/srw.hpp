#ifndef __SRW_HPP
#define __SRW_HPP

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <vector>
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
#include <Python.h>

namespace ioremap {
namespace srw {

#define SRW_TYPE_PYTHON		0

struct sph {
	uint64_t		size, binary_size;
	uint64_t		flags;
	int			pad;
	int			status;
	char			data[0];
} __attribute__ ((packed));

class python {
	public:
		python(const std::string &log_, const std::string &init_path) : log(log_.c_str(), std::ios_base::out | std::ios_base::app) {
			Py_Initialize();

			main_module = (void *)PyImport_AddModule("__main__");
			main_dict = (void *)PyModule_GetDict((PyObject *)main_module);

			FILE *fp = fopen(init_path.c_str(), "r");
			if (!fp) {
				std::ostringstream str;
				str << "could not open init file '" << init_path << "'";
				throw std::runtime_error(str.str());
			}

			PyObject *ret;
			ret = PyRun_FileExFlags(fp, init_path.c_str(), Py_file_input, (PyObject *)main_dict, (PyObject *)main_dict, true, NULL);
			if (!ret) {
				PyErr_Print();
				throw std::runtime_error("Failed to initalize python client");
			}
			Py_XDECREF(ret);

			log << getpid() << ": successfully initialized python from '" << init_path << "'" << std::endl;
		}

		virtual ~python() {
			Py_Finalize();
		}

		std::string process_data(const std::string &data, const std::string &binary) {
			PyObject* main_dict_copy = PyDict_Copy((PyObject *)main_dict);
			PyObject *tuple = NULL;

			log << getpid() << ": inside python processing callback (data size: " << data.size() <<
				", binary size: " << binary.size() << ")" << std::endl;

			if (binary.size()) {
				PyObject *bin;

				tuple = PyTuple_New(1);
				if (!tuple) {
					log << getpid() << ": could not create new tuple object" << std::endl;
					Py_XDECREF(main_dict_copy);
					throw std::bad_alloc();
				}

#if (PY_VERSION_HEX < 0x02060000)
				bin = PyBuffer_FromMemory((void *)binary.data(), binary.size());
#else
				bin = PyByteArray_FromStringAndSize(binary.data(), binary.size());
#endif
				if (!bin) {
					log << getpid() << ": could not create new binary storage object of " <<
						binary.size() << "elements" << std::endl;

					Py_XDECREF(tuple);
					Py_XDECREF(main_dict_copy);
					throw std::bad_alloc();
				}

				/* reference to 'bin' is stolen, but we do not care, since we will not use it anymore */
				PyTuple_SetItem(tuple, 0, bin);

				if (PyDict_SetItemString(main_dict_copy, "__input_binary_data_tuple", tuple)) {
					PyErr_Print();
					log << getpid() << ": could not add input binary tuple into main dict" << std::endl;

					Py_XDECREF(tuple);
					Py_XDECREF(main_dict_copy);
					throw std::runtime_error("Could not add input binary tuple into main dict");
				}
			}

			std::string ret_str;

			PyObject *ret;
			ret = PyRun_String(data.c_str(), Py_file_input, main_dict_copy, main_dict_copy);
			if (!ret) {
				PyErr_Print();
			}

			Py_XDECREF(ret);
#if 1
			ret = PyRun_String("__return_data",
					Py_eval_input, main_dict_copy, main_dict_copy);

			if (ret) {
				char *cstr;
				int size;

				if (PyArg_Parse(ret, "s#", &cstr, &size)) {
					ret_str.assign(cstr, size);
					log << getpid() << ": __return_data: " << size << " bytes" << std::endl;
				}
			}
			Py_XDECREF(ret);
#endif
			Py_XDECREF(tuple);
			Py_XDECREF(main_dict_copy);
			return ret_str;
		}

	private:
		std::ofstream log;
		void	*main_module;
		void	*main_dict;
};

class pipe {
	public:
		pipe(const std::string &pipe_base, bool worker) : base(pipe_base) {
			create_and_open(worker);
		}

		virtual ~pipe() {
			std::string p = base + ".w2c";
			unlink(p.c_str());

			p = base + ".c2w";
			unlink(p.c_str());
		}

		void read(std::string &data, std::string &binary) {
			struct sph header;
			rpipe.read((char *)&header, sizeof(struct sph));

			char *buf = new char[header.size + header.binary_size];
			try {
				rpipe.read(buf, header.size + header.binary_size);
				data.assign(buf, header.size);
				binary.assign(buf + header.size, header.binary_size);
			} catch (...) {
				delete [] buf;
				throw;
			}

			delete [] buf;
		}

		void write(int status, const std::string &data, const std::string &binary) {
			struct sph header;

			memset(&header, 0, sizeof(struct sph));
			header.size = data.size();
			header.binary_size = binary.size();
			header.status = status;

			wpipe.write((char *)&header, sizeof(struct sph));
			wpipe.write(data.data(), data.size());
			wpipe.write(binary.data(), binary.size());
			wpipe.flush();
		}

		void write(int status, const std::string &data) {
			std::string tmp;
			write(status, data, tmp);
		}

		void write(int status) {
			std::string tmp1, tmp2;
			write(status, tmp1, tmp2);
		}

	private:
		std::string base;
		std::fstream rpipe, wpipe;

		void create_fifo(const std::string &path) {
			int err;
			err = mkfifo(path.c_str(), 0644);
			if (err < 0) {
				err = -errno;
				if (err != -EEXIST) {
					std::ostringstream str;

					str << "could not create fifo '" << path << "': " << err;
					throw std::runtime_error(str.str());
				}
			}
		}

		void create_and_open(int worker) {
			std::string w2c = base + ".w2c";
			std::string c2w = base + ".c2w";

			create_fifo(w2c);
			create_fifo(c2w);

			/*
			 * Order is significant - one side must open read first while another one must open write endpoint first
			 */
			if (worker) {
				rpipe.open(c2w.c_str(), std::ios_base::in | std::ios_base::binary);
				wpipe.open(w2c.c_str(), std::ios_base::out | std::ios_base::binary);
			} else {
				wpipe.open(c2w.c_str(), std::ios_base::out | std::ios_base::binary);
				rpipe.open(w2c.c_str(), std::ios_base::in | std::ios_base::binary);
			}

			rpipe.exceptions(std::ifstream::failbit | std::ifstream::badbit);
			wpipe.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		}

};

template <class S>
class worker {
	public:
		worker(const std::string &lpath, const std::string &ppath, const std::string &init) :
			log(lpath.c_str(), std::ios_base::app), p(ppath, true) {
			s = boost::shared_ptr<S>(new S(lpath, init));
		}
		virtual ~worker() {
		}

		void process() {
			while (true) {
				std::string data, binary, ret;

				log << getpid() << ": worker: going to read new data" << std::endl;
				p.read(data, binary);
				log << getpid() << ": worker: read " << data.size() << " " << binary.size() << std::endl;
				try {
					ret = s->process_data(data, binary);
				} catch (const std::exception &e) {
					log << getpid() << ": worker: exception: " << e.what() << std::endl;
					p.write(-EINVAL);
					continue;
				}

				log << getpid() << ": worker: processing completed: " << ret.size() << " bytes" << std::endl;
				p.write(0, ret);
			}
		}

	private:
		std::ofstream log;
		pipe p;
		boost::shared_ptr<S> s;

};

class spawn {
	public:
		spawn(const std::string &bin, const std::string &log, const std::string &pipe_base, const std::string &init, int type) {
			int err;

			std::string pstr = pipe_base + ".w2c";
			unlink(pstr.c_str());

			pstr = pipe_base + ".c2w";
			unlink(pstr.c_str());

			pid = fork();
			if (pid < 0) {
				err = -errno;
				std::ostringstream str;

				str << "can not fork: " << err;
				throw std::runtime_error(str.str());
			}

			if (pid == 0) {
				std::ostringstream type_str;
				type_str << type;

				err = execl(bin.c_str(), bin.c_str(), "-l", log.c_str(), "-p", pipe_base.c_str(),
						"-i", init.c_str(), "-t", type_str.str().c_str(), NULL);

				std::ofstream l(log.c_str(), std::ios::app);
				err = -errno;
				l << getpid() << ": execl() returned " << err;
				exit(err);
			}

			int status;
			err = waitpid(pid, &status, WNOHANG);

			if (err < 0) {
				err = -errno;
				std::ostringstream str;
				str << getpid() << ": failed to waitpid: " << strerror(-err) << " : " << err;
				throw std::runtime_error(str.str());
			}

			if (err > 0 && WIFEXITED(status)) {
				err = WEXITSTATUS(status);

				std::ostringstream str;
				str << "Pid " << pid << " exited: " << strerror(-err) << " : " << err;
				throw std::runtime_error(str.str());
			}

			p = boost::shared_ptr<pipe>(new pipe(pipe_base, false));
		}

		virtual ~spawn() {
			kill(pid, SIGTERM);
			wait(NULL);
		}

		boost::shared_ptr<pipe> p;
		int pid;
};

typedef boost::shared_ptr<spawn> shared_proc_t;
class pool {
	public:
		pool(const std::string &bin, const std::string &log_file,
				const std::string &pipe_base, const std::string &init, int type, int num) : log(log_file.c_str(), std::ios::app) {
			for (int i = 0; i < num; ++i) {
				shared_proc_t sp(new spawn(bin, log_file, pipe_base, init, type));

				boost::mutex::scoped_lock guard(lock);
				vec.push_back(sp);
			}
		}

		virtual ~pool() {
		}

		void drop(int pid) {
			boost::mutex::scoped_lock guard(lock);
			shared_proc_t sp;

			for (std::vector<shared_proc_t>::iterator it = vec.begin(); it < vec.end(); ++it) {
				sp = *it;

				if (sp->pid == pid) {
					vec.erase(it);
					break;
				}
			}
		}

		std::string process(const std::string &data, const std::string &binary) {
			std::string ret;
			shared_proc_t sp;
			bool have_worker = false;

			log << getpid() << ": going to process new data" << std::endl;
			{
				boost::mutex::scoped_lock guard(lock);

				while (vec.empty()) {
					cond.wait(guard);
				}


				sp = vec.front();

				vec.erase(vec.begin());
				have_worker = true;
			}

			if (have_worker) {
				try {
					log << getpid() << ": writing new data: " << data.size() << " " << binary.size() << std::endl;
					sp->p->write(0, data, binary);

					log << getpid() << ": reading reply data" << std::endl;
					std::string tmp;
					sp->p->read(ret, tmp);
					log << getpid() << ": read reply data: " << ret.size() << " bytes" << std::endl;
				} catch (const std::exception &e) {
					log << getpid() << ": processing exception: " << e.what() << std::endl;

					boost::mutex::scoped_lock guard(lock);
					vec.push_back(sp);
					guard.unlock();

					cond.notify_one();

					throw;
				}

				boost::mutex::scoped_lock guard(lock);
				vec.push_back(sp);
				guard.unlock();

				cond.notify_one();
			}

			return ret;
		}

	private:
		std::ofstream log;
		boost::mutex lock;
		boost::condition cond;
		std::vector<shared_proc_t> vec;
		std::vector<shared_proc_t> in_use;
};

} /* namespace srw */
} /* namespace ioremap */
#endif
