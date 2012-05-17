#ifndef __ELLIPTICS_SRW_PYTHON_HPP
#define __ELLIPTICS_SRW_PYTHON_HPP

#include <elliptics/srw/pipe.hpp>

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#ifdef _XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif

#include <Python.h>

namespace ioremap {
namespace srw {

class python {
	public:
		python(const std::string &log, const std::string &init_path, const std::string &) :
				m_log(log.c_str(), std::ios_base::out | std::ios_base::app),
       				m_fp(NULL), m_python_log_file(NULL) {
			Py_Initialize();

			m_main_module = (void *)PyImport_AddModule("__main__");
			m_main_dict = (void *)PyModule_GetDict((PyObject *)m_main_module);

			m_fp = fopen(init_path.c_str(), "r");
			if (!m_fp) {
				std::ostringstream str;
				str << "could not open init file '" << init_path << "'";
				throw std::runtime_error(str.str());
			}

			m_python_log_file = PyFile_FromString((char *)log.c_str(), (char *)"a");
			if (!m_python_log_file) {
				fclose(m_fp);
				std::ostringstream str;
				str << "could not open m_log file '" << log << "'";
				throw std::runtime_error(str.str());
			}

			int err;

			err = PySys_SetObject((char *)"stdout", m_python_log_file);
			if (err) {
				fclose(m_fp);
				Py_XDECREF(m_python_log_file);
				std::ostringstream str;
				str << "could set stdout to '" << log << "'";
				throw std::runtime_error(str.str());
			}

			err = PySys_SetObject((char *)"stderr", m_python_log_file);
			if (err) {
				fclose(m_fp);
				Py_XDECREF(m_python_log_file);
				std::ostringstream str;
				str << "could set stderr to '" << log << "'";
				throw std::runtime_error(str.str());
			}

			PySys_WriteStdout("%d: this is a python stdout test\n", getpid());

			PyObject *ret;
			ret = PyRun_FileExFlags(m_fp, init_path.c_str(), Py_file_input,
					(PyObject *)m_main_dict, (PyObject *)m_main_dict, true, NULL);
			if (!ret) {
				PyErr_Print();
				Py_XDECREF(m_python_log_file);
				throw std::runtime_error("Failed to initalize python client");
			}
			Py_XDECREF(ret);

			m_log << getpid() << ": successfully initialized python from '" << init_path << "'" << std::endl;
		}

		virtual ~python() {
			Py_XDECREF(m_python_log_file);
			Py_Finalize();
		}

		std::string process_data(struct sph &header, const std::string &data) {
			PyObject* m_main_dict_copy = PyDict_Copy((PyObject *)m_main_dict);
			PyObject *tuple = NULL;

			m_log << getpid() << ": inside python processing callback (data size: " << header.data_size <<
				", binary size: " << header.binary_size << ")" << std::endl;

			if (header.binary_size) {
				const char *binary = (char *)data.data() + header.data_size;
				PyObject *bin;

				tuple = PyTuple_New(1);
				if (!tuple) {
					m_log << getpid() << ": could not create new tuple object" << std::endl;
					Py_XDECREF(m_main_dict_copy);
					header.status = -ENOMEM;
					throw std::bad_alloc();
				}

#if (PY_VERSION_HEX < 0x02060000)
				bin = PyBuffer_FromMemory((void *)binary, header.binary_size);
#else
				bin = PyByteArray_FromStringAndSize(binary, header.binary_size);
#endif
				if (!bin) {
					m_log << getpid() << ": could not create new binary storage object of " <<
						header.binary_size << "elements" << std::endl;

					Py_XDECREF(tuple);
					Py_XDECREF(m_main_dict_copy);
					header.status = -ENOMEM;
					throw std::bad_alloc();
				}

				/* reference to 'bin' is stolen, but we do not care, since we will not use it anymore */
				PyTuple_SetItem(tuple, 0, bin);

				if (PyDict_SetItemString(m_main_dict_copy, "__input_binary_data_tuple", tuple)) {
					PyErr_Print();
					m_log << getpid() << ": could not add input binary tuple into main dict" << std::endl;

					Py_XDECREF(tuple);
					Py_XDECREF(m_main_dict_copy);
					header.status = -ENOMEM;
					throw std::runtime_error("Could not add input binary tuple into main dict");
				}
			}

			std::string ret_str;

			PyObject *ret;
			ret = PyRun_String(data.c_str(), Py_file_input, m_main_dict_copy, m_main_dict_copy);
			if (!ret) {
				PyErr_Print();
				header.status = -EINVAL;
			}

			Py_XDECREF(ret);
#if 1
			ret = PyRun_String("__return_data",
					Py_eval_input, m_main_dict_copy, m_main_dict_copy);

			if (ret) {
				char *cstr;
				int size;

				if (PyArg_Parse(ret, "s#", &cstr, &size)) {
					ret_str.assign(cstr, size);
				}
			}
			Py_XDECREF(ret);
#endif
			Py_XDECREF(tuple);
			Py_XDECREF(m_main_dict_copy);
			return ret_str;
		}

	private:
		std::ofstream m_log;
		void	*m_main_module;
		void	*m_main_dict;
		FILE	*m_fp;
		PyObject	*m_python_log_file;
};

}}

#endif /* __ELLIPTICS_SRW_PYTHON_HPP */
