#include "config.h"

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>

#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <elliptics/cppdef.h>

extern "C" {
#include <eblob/blob.h>
}


class processor_key {
	public:
		std::string path;
		uint64_t offset;
		uint64_t size;
		std::string id;
};

class generic_processor {
	public:
		virtual processor_key next(void) = 0;
};

class eblob_processor : public generic_processor {
	public:
		eblob_processor(const std::string &path) : path_(path), index_(0) {
			open_index();
		}

		virtual ~eblob_processor() {
			if (file_.is_open())
				file_.close();
		}

		processor_key next(void) {
			struct eblob_disk_control dc;
			processor_key key;

			while (true) {
				if (pos_ >= file_.size()) {
					open_index();
				}

				memcpy(&dc, file_.const_data() + pos_, sizeof(dc));

				std::cout << "offset: " << dc.position << ", size: " << dc.data_size << ", disk_size: " << dc.disk_size << std::endl;

				pos_ += sizeof(dc);

				if (!(dc.flags & BLOB_DISK_CTL_REMOVE)) {
					key.id.assign((char *)dc.id, sizeof(dc.id));
					key.path = path_ + "." + boost::lexical_cast<std::string>(index_ - 1);
					key.offset = dc.position + sizeof(dc);
					key.size = dc.data_size;
					break;
				}
			}

			return key;
		}

	private:
		std::string path_;
		int index_;
		uint64_t pos_;
		boost::iostreams::mapped_file file_;

		void open_index() {
			std::ostringstream filename;

			pos_ = 0;

			if (file_.is_open())
				file_.close();

			filename << path_ << "." << index_ << ".index";
			file_.open(filename.str(), std::ios_base::in | std::ios_base::binary);

			++index_;
		}
};

class fs_processor : public generic_processor {
	public:
		fs_processor(const std::string &path) : itr_(fs::path(path)) {
		}

		processor_key next(void) {
			processor_key key;

			while (true) {
				if (itr_ == end_itr_) {
					throw std::runtime_error("Whole directory has been traversed");
				}

				if (fs::is_directory(itr_->path())) {
					++itr_;
					continue;
				}

				if (itr_->leaf().size() != DNET_ID_SIZE * 2) {
					++itr_;
					continue;
				}

				parse(itr_->leaf(), key.id);
				key.path = itr_->path().string();
				key.offset = 0;
				key.size = 0;

				std::cout << "fs: " << itr_->path() << std::endl;

				++itr_;
				break;
			}
			return key;
		}

	private:
		fs::recursive_directory_iterator end_itr_, itr_;
		std::vector<std::string> dirs_;

		void parse(const std::string &value, std::string &key) {
			unsigned char ch[5];
			unsigned int i, len = value.size();
			unsigned char id[DNET_ID_SIZE];

			memset(id, 0, DNET_ID_SIZE);

			if (len/2 > DNET_ID_SIZE)
				len = DNET_ID_SIZE * 2;

			ch[0] = '0';
			ch[1] = 'x';
			ch[4] = '\0';
			for (i=0; i<len / 2; i++) {
				ch[2] = value[2*i + 0];
				ch[3] = value[2*i + 1];

				id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
			}

			if (len & 1) {
				ch[2] = value[2*i + 0];
				ch[3] = '0';

				id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
			}

			key.assign((char *)id, DNET_ID_SIZE);
		}

};

class remote_update {
	public:
		remote_update(const std::vector<int> groups) : groups_(groups), aflags_(DNET_ATTR_DIRECT_TRANSACTION) {
		}

		void process(elliptics_node &n, const std::string &path, int tnum = 16, int csum_enabled = 0) {
			generic_processor *proc;

			if (!csum_enabled)
				aflags_ |= DNET_ATTR_NOCSUM;

			if (fs::is_directory(fs::path(path))) {
				proc = new fs_processor(path);
			} else {
				proc = new eblob_processor(path);
			}

			try {
				boost::thread_group threads;
				for (int i=0; i<tnum; ++i) {
					threads.create_thread(boost::bind(&remote_update::process_data, this, proc, &n));
				}

				threads.join_all();
			} catch (const std::exception &e) {
				std::cerr << "Finished processing " << path << " : " << e.what() << std::endl;
				delete proc;
				throw e;
			}

			delete proc;
		}

	private:
		std::vector<int> groups_;
		boost::mutex data_lock_;
		int aflags_;

		void update(elliptics_node *n, processor_key &key) {
			struct dnet_id id;
			struct dnet_meta *m;

			for (int i=0; i<(int)groups_.size(); ++i) {
				dnet_setup_id(&id, groups_[i], (unsigned char *)key.id.data());

				std::string meta, data;

				try {
					data = n->read_data_wait(id, 1, 0);
				} catch (...) {
				}

				if (!data.size()) {
					std::cout << dnet_dump_id(&id) << ": sending " << key.path << " offset " << key.offset << " size " << key.size << std::endl;
					n->write_file(id, (char *)key.path.c_str(), key.offset, 0, key.size, DNET_ATTR_DIRECT_TRANSACTION, 0);
				} else {
					try {
						meta = n->read_data_wait(id, 0, 0, aflags_, DNET_IO_FLAGS_META);
					} catch (...) {
					}

					m = dnet_meta_search(NULL, (void *)meta.data(), meta.size(), DNET_META_GROUPS);
					if (m)
						continue;

					char buf[sizeof(struct dnet_meta) + sizeof(int) * groups_.size()];

					memset(buf, 0, sizeof(struct dnet_meta));

					m = (struct dnet_meta *)buf;

					m->type = DNET_META_GROUPS;
					m->size = sizeof(int) * groups_.size();

					memcpy(m->data, groups_.data(), groups_.size() * sizeof(int));

					std::string meta;
					meta.assign(buf, sizeof(buf));

					n->write_data_wait(id, meta, DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_META | DNET_IO_FLAGS_APPEND);
				}
			}
		}

		void process_data(generic_processor *proc, elliptics_node *n) {
			try {
				while (true) {
					processor_key key;

					{
						boost::mutex::scoped_lock scoped_lock(data_lock_);
						key = proc->next();
					}

					update(n, key);
				}
			} catch (...) {
			}
		}
};

int main(int argc, char *argv[])
{
	try {
		namespace po = boost::program_options;
		po::options_description desc("Options (required options are marked with *");
		int groups_array[] = {1};
		std::vector<int> groups(groups_array, groups_array + ARRAY_SIZE(groups_array));
		int log_mask;
		std::string log_file;
		std::string addr;
		int port, family;
		int thread_num;
		int csum_enabled;

		desc.add_options()
			("help", "This help message")
			("input-path", po::value<std::string>(), "Input path (*)")
			("log-file", po::value<std::string>(&log_file)->default_value("/dev/stdout"), "Log file")
			("log-mask", po::value<int>(&log_mask)->default_value(DNET_LOG_ERROR | DNET_LOG_INFO), "Log mask")
			("threads", po::value<int>(&thread_num)->default_value(16), "Number of threads to iterate over input data")
			("group", po::value<std::vector<int> >(&groups), "Group number which will host given object, can be used multiple times for several groups")
			("remote-addr", po::value<std::string>(&addr)->default_value("localhost"), "Connect to this remote node")
			("remote-port", po::value<int>(&port)->default_value(1025), "Connect to this remote port")
			("addr-family", po::value<int>(&family)->default_value(AF_INET), "Address family (2 - IPv4, 6 - IPv6)")
			("enable-checksum", po::value<int>(&csum_enabled)->default_value(0), "Set to 1 if you want to enable server generated checksums")
		;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help") || !vm.count("input-path")) {
			std::cout << desc << "\n";
			return -1;
		}

		if (vm.count("log-file"))
			log_file = vm["log-file"].as<std::string>().data();
		if (vm.count("log-mask"))
			log_mask = vm["log-mask"].as<int>();

		elliptics_log_file log(log_file.data(), log_mask);

		elliptics_node node(log);
		node.add_groups(groups);
		node.add_remote(addr.c_str(), port, family);

		remote_update up(groups);
		up.process(node, vm["input-path"].as<std::string>(), thread_num, csum_enabled);
	} catch (const std::exception &e) {
		std::cerr << "Exiting: " << e.what() << std::endl;
	}
}
