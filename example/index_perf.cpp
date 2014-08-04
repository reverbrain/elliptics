#include <elliptics/session.hpp>
#include <elliptics/timer.hpp>

#include <boost/program_options.hpp>

#include <iostream>

using namespace ioremap;

int main(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::options_description generic("Index performance tool options");

	int data_size, num;
	std::string log_level_name;
	std::string log, remote, index, groups;

	generic.add_options()
		("help", "This help message")
		("log", bpo::value<std::string>(&log)->default_value("/dev/stdout"), "Elliptics log file")
		("log-level", bpo::value<std::string>(&log_level_name)->default_value("info"), "Elliptics log level")
		("remote", bpo::value<std::string>(&remote), "Elliptics remote node to connect to")
		("groups", bpo::value<std::string>(&groups), "Elliptics remote groups to work with")
		("index", bpo::value<std::string>(&index)->default_value("test-index"), "Elliptics secondary index name")
		("num", bpo::value<int>(&num)->default_value(1000000), "Number of entries to put into the index")
		("size", bpo::value<int>(&data_size)->default_value(100), "Size of every index entry")
		;

	bpo::options_description cmdline_options;
	cmdline_options.add(generic);

	bpo::variables_map vm;
	dnet_log_level log_level;

	try {
		bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).run(), vm);

		if (vm.count("help")) {
			std::cout << generic << std::endl;
			return 0;
		}

		bpo::notify(vm);

		log_level = elliptics::file_logger::parse_level(log_level_name);
	} catch (const std::exception &e) {
		std::cerr << "Invalid options: " << e.what() << "\n" << generic << std::endl;
		return -1;
	}


	elliptics::file_logger logger(log.c_str(), log_level);
	elliptics::node node(elliptics::logger(logger, blackhole::log::attributes_t()));

	try {
		node.add_remote(remote);

		elliptics::session session(node);
		session.set_groups(elliptics::parse_groups(groups.c_str()));

		elliptics::data_pointer index_data = elliptics::data_pointer::allocate(data_size);

		for (int i = 0; i < num;) {
			int wait_size = 1000;
			std::vector<elliptics::async_set_indexes_result> wait;
			wait.reserve(wait_size);

			std::vector<std::string> indexes;
			std::vector<elliptics::data_pointer> datas;

			indexes.push_back(index);
			datas.push_back(index_data);

			elliptics::timer tm;
			for (int j = 0; j < wait_size && i < num; ++j, ++i) {
				std::string key = "test-" + elliptics::lexical_cast(i);

				wait.emplace_back(session.set_indexes(key, indexes, datas));
			}

			for (size_t j = 0; j < wait.size(); ++j) {
				wait[j].wait();
			}

			printf("processed keys: %d/%d, speed: %.3f updates/sec\n",
					i, num, (double)(wait.size() * 1000) / (double)tm.elapsed());
		}
	} catch (const std::exception &e) {
		std::cerr << "Exception caught: " << e.what() << std::endl;
		return -1;
	}

}
