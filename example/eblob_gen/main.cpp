#include "config.h"

#include <boost/program_options.hpp>

#include "eblob_gen.h"

#include "common.h"

eblob_processor::eblob_processor(const bool prepend_data, std::vector<int> &groups, const std::string &eblob_base, const struct eblob_config &cfg) :
	prepend_data_(prepend_data),
	groups_(groups),
	eblob_cfg_(cfg),
	eblob_base_(eblob_base)
{
}

void eblob_processor::process(elliptics_node &node, const std::string &path)
{
	std::string data, name;
	bool have_data = false;
	eblob_data_source *source;
	struct dnet_id id;
	struct timeval tv;
	struct timespec ts;

	if (fs::is_directory(fs::path(path))) {
		source = new eblob_dir_source(path);
	} else {
		source = new eblob_tar_source(path);
	}

	gettimeofday(&tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	do {
		try {
			have_data = source->next(prepend_data_, NULL, name, data);
			if (!have_data)
				break;

			node.transform(name, id);
			node.write_metadata(id, name, groups_, ts);

			std::vector<int>::const_iterator end_itr = groups_.end();
			for (std::vector<int>::const_iterator itr = groups_.begin(); itr != end_itr; ++itr) {
				int group_id = *itr;

				id.group_id = group_id;

				try {
					std::map<std::string, boost::shared_ptr<eblob> >::iterator res;

					std::string addr = node.lookup_addr(name, group_id);
					res = blobs.find(addr);

					std::cout << name << ": size: " << data.size() << ", key: " << dnet_dump_id(&id) << " -> " << addr << std::endl;

					if (res == blobs.end()) {
						fs::create_directory(eblob_base_ + "/" + addr);

						std::string file = eblob_base_ + "/" + addr + "/data";
						eblob_cfg_.file = (char *)file.c_str();

						boost::shared_ptr<eblob> e(new eblob(eblob_cfg_));

						blobs[addr] = e;

						e->write(id, data);
					} else {
						res->second->write(id, data);
					}

				} catch (std::exception &e) {
					std::cerr << "Failed to lookup and write key " << name << " : " << e.what() << std::endl;
				}
			}
		} catch (std::exception &e) {
			std::cerr << "Can not handle next data source: " << e.what() << std::endl;
		}
	} while (have_data);

	delete source;
}

int main(int argc, char *argv[])
{
	try {
		namespace po = boost::program_options;
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
			("blob-base", po::value<std::string>(&eblob_base)->default_value("./"),
			 	"Base filename for eblobs, system will append $address.N "
				"where N is index of the blob and $address is the address which should host given blob(*)")
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

		if (vm.count("help") || !vm.count("input-path")) {
			std::cout << desc << "\n";
			return -1;
		}

		if (vm.count("log-file"))
			log_file = vm["log-file"].as<std::string>().data();
		if (vm.count("log-mask"))
			log_mask = vm["log-mask"].as<int>();

		elliptics_log_file log(log_file.data(), log_mask);
		cfg.log = (struct eblob_log *)log.get_dnet_log();

		elliptics_node node(log);
		node.add_groups(groups);
		node.add_remote(addr.c_str(), port, family);

		eblob_processor proc(prepend_timestamp, groups, eblob_base, cfg);
		proc.process(node, vm["input-path"].as<std::string>());
	} catch (std::exception &e) {
		std::cerr << "Exception: " << e.what() << "\n";
	}

	return 0;
}
