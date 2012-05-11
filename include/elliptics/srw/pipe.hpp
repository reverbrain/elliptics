#ifndef __ELLIPTICS_SRW_PIPE_HPP
#define __ELLIPTICS_SRW_PIPE_HPP

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <sstream>

#include <boost/thread/mutex.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/condition.hpp>

#include <elliptics/srw/base.h>

namespace ioremap {
namespace srw {

class pipe {
	public:
		pipe(const std::string &pipe_base, bool worker) : base(pipe_base) {
			create_and_open(worker);
		}

		virtual ~pipe() {
			std::string m_p = base + ".w2c";
			unlink(m_p.c_str());

			m_p = base + ".c2w";
			unlink(m_p.c_str());
		}

		void read(struct sph &header, std::string &data) {
			rpipe.read((char *)&header, sizeof(struct sph));

			data.resize(hsize(header));
			rpipe.read((char *)data.data(), hsize(header));
		}

		void write(struct sph &header, const char *data) {
			wpipe.write((char *)&header, sizeof(struct sph));

			if (header.data_size && data)
				wpipe.write(data, hsize(header));

			wpipe.flush();
		}

	private:
		std::string base;
		std::fstream rpipe, wpipe;

		size_t hsize(struct sph &header) {
			return header.data_size + header.binary_size + header.event_size;
		}

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

}}

#endif /* __ELLIPTICS_SRW_PIPE_HPP */
