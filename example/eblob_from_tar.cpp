#include "config.h"

#include <time.h>

#include <iostream>
#include <fstream>
#include <string>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <boost/program_options.hpp>
#include <boost/filesystem/operations.hpp>

extern "C" {
#include <eblob/blob.h>
}
#include "elliptics/cppdef.h"

#include "common.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

class eblob {
	public:
		eblob(elliptics_log &l, struct eblob_config &cfg, const bool prepend_timestamp = false);
		virtual ~eblob();

		bool prepend_timestamp() {return prepend_timestamp_;}
		void write(const std::string &name, const std::string &data);

		void add_remote(const char *addr, const int port, const int family = AF_INET);
		void add_groups(std::vector<int> &groups);
	private:
		struct eblob_backend *blob;
		elliptics_node node;

		bool prepend_timestamp_;
};

eblob::eblob(elliptics_log &l, struct eblob_config &cfg, const bool prepend_timestamp) :
	node(l),
	prepend_timestamp_(prepend_timestamp)
{
	blob = eblob_init(&cfg);
	if (!blob)
		throw std::runtime_error("Failed to initialize eblob");
#if 0
	std::vector<int>::const_iterator end_itr = groups_.end();
	for (std::vector<int>::const_iterator itr = groups_.begin(); itr != end_itr; ++itr)
		std::cout << (*itr) << std::endl;
#endif
}

eblob::~eblob()
{
	eblob_cleanup(blob);
}

void eblob::add_groups(std::vector<int> &groups)
{
	node.add_groups(groups);
}

void eblob::add_remote(const char *addr, const int port, const int family)
{
	try {
		node.add_remote(addr, port, family);
	} catch (...) {
		std::ostringstream str;

		str << "Failed to connect to " << addr << ":" << port;
		throw std::runtime_error(str.str());
	}
}

void eblob::write(const std::string &name, const std::string &data)
{
	int err;
	struct dnet_id id;

	node.transform(name, id);

	err = eblob_write_data(blob, id.id, sizeof(id.id), (void *)data.data(), data.size(), 0);
	if (err) {
		std::ostringstream str;
		str << "Failed to write into eblob: key: " << dnet_dump_id_len(&id, DNET_ID_SIZE) << ", data size: " << data.size() << std::endl;
		throw std::runtime_error(str.str());
	}

	node.write_metadata(id, name, node.get_groups());
}

static void ebf_process_dir(const fs::path &p, eblob &e)
{
	fs::directory_iterator end_itr;

	for (fs::directory_iterator itr(p); itr != end_itr; ++itr) {
		try {
			if (!is_regular_file(*itr))
				continue;

			std::ifstream file(itr->path().string().c_str(), std::ios::binary | std::ios::in);
			std::filebuf *pbuf = file.rdbuf();
			std::stringstream data;

			if (e.prepend_timestamp()) {
				int err, bufsize;
				struct timespec ts;
				size_t size;
				char *buf;

				ts.tv_sec = (long)time(NULL);
				ts.tv_nsec = 0;

				size = pbuf->pubseekoff(0, std::ios::end, std::ios::in);
				pbuf->pubseekpos(0, std::ios::in);

				bufsize = 128;
				buf = new char[bufsize];

				try {
					err = dnet_common_prepend_data(&ts, size, buf, &bufsize);
					if (err)
						throw std::runtime_error("Not enough buf");
					data.write(buf, bufsize);
				} catch (...) {
					delete [] buf;
					throw;
				}
				delete [] buf;
			}

			data << pbuf;

			std::cout << *itr << " : " << itr->path().string() << " " << data.str().size() << std::endl;

			e.write(itr->path().filename(), data.str());

		} catch (std::exception e) {
			std::cerr << "Failed to process " << *itr << ": " << e.what() << std::endl;
		}
	}
}

static void ebf_process(std::string path, eblob &e)
{
	fs::path p(path);

	if (is_directory(p)) {
		std::cout << path << " is directory\n";
		ebf_process_dir(p, e);
	} else {
		std::cout << path << " is file\n";
	}
}

static int ebf_fill_config(struct eblob_config &cfg, po::variables_map &vm)
{
	memset(&cfg, 0, sizeof(cfg));

	if (vm.count("hash-table-size"))
		cfg.hash_size = vm["hash-table-size"].as<unsigned long long>();
	if (vm.count("hash-table-flags"))
		cfg.hash_flags = vm["hash-table-flags"].as<int>();
	if (vm.count("sync-interval"))
		cfg.sync = vm["sync-interval"].as<int>();
	if (vm.count("blob-base"))
		cfg.file = (char *)vm["blob-base"].as<std::string>().data();
	if (vm.count("blob-size"))
		cfg.blob_size = vm["blob-size"].as<unsigned long long>();

	return 0;
}

int main(int argc, char *argv[])
{
	try {
		po::options_description desc("Options (required options are marked with *");
		struct eblob_config cfg;
		int log_mask;
		std::string log_file;
		std::string eblob_base;
		std::string addr;
		int port, family;
		bool prepend_timestamp;
		int groups_array[] = {1};
		std::vector<int> groups(groups_array, groups_array + ARRAY_SIZE(groups_array));

		memset(&cfg, 0, sizeof(cfg));

		desc.add_options()
			("help", "This help message")
			("input-path", po::value<std::string>(), "Input path (*)")
			("hash-table-size", po::value<unsigned int>(&cfg.hash_size), "Number of buckets in eblob hash table")
			("hash-table-flags", po::value<unsigned int>(&cfg.hash_flags), "Eblob hash table flags")
			("sync-interval", po::value<int>(&cfg.sync), "Eblob sync interval in seconds")
			("log-file", po::value<std::string>(&log_file)->default_value("/dev/stdout"), "Log file")
			("log-mask", po::value<int>(&log_mask)->default_value(EBLOB_LOG_ERROR | EBLOB_LOG_INFO),
			 	"Log mask (1 - notice, 2 - info, 8 - error, 16 - state updates (huge and kinda useless)")
			("blob-base", po::value<std::string>(&eblob_base), "Base filename for eblobs, system will append .N where N is index of the blob (*)")
			("blob-size", po::value<unsigned long long>((unsigned long long *)&cfg.blob_size), "Single eblob size in bytes")
			("prepend-timestamp", po::value<bool>(&prepend_timestamp)->default_value(false), "Whether to prepend data ith timestamp")
			("group", po::value<std::vector<int> >(&groups), "Group number which will host given object, can be used multiple times for several groups")
			("remote-addr", po::value<std::string>(&addr)->default_value("localhost"), "Connect to this remote node")
			("remote-port", po::value<int>(&port)->default_value(1025), "Connect to this remote port")
			("addr-family", po::value<int>(&family)->default_value(AF_INET), "Address family (2 - IPv4, 6 - IPv6)")
		;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help") || !vm.count("input-path") || !vm.count("blob-base")) {
			std::cout << desc << "\n";
			return -1;
		}

		if (vm.count("log-file"))
			log_file = vm["log-file"].as<std::string>().data();
		if (vm.count("log-mask"))
			log_mask = vm["log-mask"].as<int>();

		cfg.file = (char *)vm["blob-base"].as<std::string>().data();

		elliptics_log_file log(log_file.data(), log_mask);
		cfg.log = (struct eblob_log *)log.get_dnet_log();

		eblob e(log, cfg, prepend_timestamp);
		e.add_groups(groups);
		e.add_remote(addr.c_str(), port, family);

		ebf_process(vm["input-path"].as<std::string>(), e);
	} catch (std::exception &e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
