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
#include <boost/algorithm/string.hpp>

#include <elliptics/packet.h>

namespace ioremap {
namespace srw {

static inline std::string get_event(const struct sph &header, const char *data) {
	std::string event;
	event.assign(data, header.event_size);

	return event;
}

static inline std::string get_app(const struct sph &header, const char *data) {
	std::string event;
	event.assign(data, header.event_size);

	std::vector<std::string> strs;
	boost::split(strs, event, boost::is_any_of("/"));

	return strs[0];
}

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
			if (hsize(header))
				rpipe.read((char *)data.data(), hsize(header));
		}

		void write(struct sph &header, const char *data) {
			wpipe.write((char *)&header, sizeof(struct sph));

			if (hsize(header) && data)
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
