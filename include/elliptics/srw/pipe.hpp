#ifndef __ELLIPTICS_SRW_PIPE_HPP
#define __ELLIPTICS_SRW_PIPE_HPP

#include <elliptics/srw/base.hpp>

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

}}

#endif /* __ELLIPTICS_SRW_PIPE_HPP */
