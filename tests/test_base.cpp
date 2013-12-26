#include "test_base.hpp"
#include "../example/common.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include <fstream>
#include <set>

namespace tests {

ioremap::elliptics::session create_session(ioremap::elliptics::node n, std::initializer_list<int> groups, uint64_t cflags, uint32_t ioflags)
{
	session sess(n);

	sess.set_groups(std::vector<int>(groups));
	sess.set_cflags(cflags);
	sess.set_ioflags(ioflags);

	sess.set_exceptions_policy(session::no_exceptions);

	return sess;
}


directory_handler::directory_handler() : m_remove(false)
{
}

directory_handler::directory_handler(const std::string &path, bool remove) : m_path(path), m_remove(remove)
{
}

directory_handler::directory_handler(directory_handler &&other) : m_path(other.m_path), m_remove(other.m_remove)
{
	other.m_path.clear();
}

directory_handler &directory_handler::operator=(directory_handler &&other)
{
	std::swap(m_path, other.m_path);
	std::swap(m_remove, other.m_remove);

	return *this;
}

std::string directory_handler::path() const
{
	return m_path;
}

directory_handler::~directory_handler()
{
	if (!m_path.empty() && m_remove)
		boost::filesystem::remove_all(m_path);
}

void create_directory(const std::string &path)
{
	// Boost throws exception on fail
	boost::filesystem::create_directory(path);
}

#ifndef NO_SERVER

config_data &config_data::operator()(const std::string &name, const std::string &value)
{
	for (auto it = m_data.begin(); it != m_data.end(); ++it) {
		if (it->first == name) {
			it->second = value;
			return *this;
		}
	}

	m_data.emplace_back(name, value);

	return *this;
}

config_data &config_data::operator()(const std::string &name, int value)
{
	return (*this)(name, boost::lexical_cast<std::string>(value));
}

config_data &config_data::operator()(const std::string &name, dummy_value_type type)
{
	if (type == NULL_VALUE) {
		for (auto it = m_data.begin(); it != m_data.end(); ++it) {
			if (it->first == name) {
				m_data.erase(it);
				return *this;
			}
		}

		return *this;
	}

	return (*this)(name, "dummy-value");
}

config_data config_data::default_srw_value()
{
	return config_data()
			("log", "/dev/stderr")
			("log_level", DNET_LOG_DEBUG)
			("join", 1)
			("flags", 4)
			("group", DUMMY_VALUE)
			("addr", DUMMY_VALUE)
			("remote", DUMMY_VALUE)
			("wait_timeout", 60)
			("check_timeout", 60)
			("io_thread_num", 50)
			("nonblocking_io_thread_num", 16)
			("net_thread_num", 16)
			("history", DUMMY_VALUE)
			("daemon", 0)
			("auth_cookie", DUMMY_VALUE)
			("bg_ionice_class", 3)
			("bg_ionice_prio", 0)
			("server_net_prio", 1)
			("client_net_prio", 6)
			("cache_size", 1024 * 1024 * 256)
			("caches_number", 16)
			("srw_config", DUMMY_VALUE)
			("backend", "blob")
			("sync", 5)
			("data", DUMMY_VALUE)
			("data_block_size", 1024)
			("blob_flags", 6)
			("iterate_thread_num", 1)
			("blob_size", "10M")
			("records_in_blob", 10000000)
			("defrag_timeout", 3600)
			("defrag_percentage", 25);
}

config_data config_data::default_value()
{
	return default_srw_value()("srw_config", NULL_VALUE);
}

bool config_data::has_value(const std::string &name) const
{
	for (auto it = m_data.begin(); it != m_data.end(); ++it) {
		if (it->first == name) {
			return true;
		}
	}

	return false;
}

config_data_writer::config_data_writer(const config_data_writer &other)
	: config_data(other), m_path(other.m_path)
{
}

config_data_writer::config_data_writer(const config_data &other, const std::string &path)
	: config_data(other), m_path(path)
{
}

config_data_writer::~config_data_writer()
{
	write();
}

void config_data_writer::write()
{
	std::ofstream out;
	out.open(m_path.c_str());

	if (!out) {
		throw std::runtime_error("Can not open file \"" + m_path + "\" for writing");
	}

	for (auto it = m_data.begin(); it != m_data.end(); ++it) {
		if (it->second == "dummy-value")
			throw std::runtime_error("Unset value for key \"" + it->first + "\", file: \"" + m_path + "\"");

		out << it->first << " = " << it->second << std::endl;
	}

	out.flush();
	out.close();
}

server_node::server_node() : m_node(NULL)
{
}

server_node::server_node(const std::string &path, const std::string &remote) : m_node(NULL), m_path(path), m_remote(remote)
{
}

server_node::server_node(server_node &&other) :
	m_node(other.m_node), m_path(std::move(other.m_path)), m_remote(std::move(other.m_remote))
{
	other.m_node = NULL;
}

server_node &server_node::operator =(server_node &&other)
{
	std::swap(m_node, other.m_node);
	std::swap(m_path, other.m_path);
	std::swap(m_remote, other.m_remote);

	return *this;
}

server_node::~server_node()
{
	if (m_node)
		stop();
}

void server_node::start()
{
	if (m_node)
		throw std::runtime_error("Server node \"" + m_path + "\" is already started");

	m_node = dnet_parse_config(m_path.c_str(), 0);
	if (!m_node)
		throw std::runtime_error("Can not start server with config file: \"" + m_path + "\"");
}

void server_node::stop()
{
	if (!m_node)
		throw std::runtime_error("Server node \"" + m_path + "\" is already stoped");

	dnet_set_need_exit(m_node);
	while (!dnet_need_exit(m_node))
		sleep(1);

	dnet_server_node_destroy(m_node);
	m_node = NULL;
}

std::string server_node::remote() const
{
	return m_remote;
}

dnet_node *server_node::get_native()
{
	return m_node;
}

static config_data_writer create_config(config_data base_config, const std::string &path)
{
	return config_data_writer(base_config, path);
}

static std::vector<std::string> generate_ports(size_t count)
{
	std::set<std::string> ports;
	while (ports.size() < count) {
		// Random port from 10000 to 60000
		int port = 10000 + (rand() % 50000);
		ports.insert(boost::lexical_cast<std::string>(port));
	}

	return std::vector<std::string>(ports.begin(), ports.end());
}

static std::string create_remote(const std::string &port)
{
	return "localhost:" + port + ":2";
}

typedef std::map<std::string, std::string> substitute_context;
static void create_cocaine_config(const std::string &config_path, const std::string& template_text, const substitute_context& vars)
{
	std::string config_text = template_text;

	for (auto it = vars.begin(); it != vars.end(); ++it) {
		auto position = config_text.find(it->first);
		if (position != std::string::npos)
			config_text.replace(position, it->first.size(), it->second);
	}

	std::ofstream out;
	out.open(config_path.c_str());

	if (!out) {
		throw std::runtime_error("Can not open file \"" + config_path + "\" for writing");
	}

	out.write(config_text.c_str(), config_text.size());
}

static void start_client_nodes(const nodes_data::ptr &data, std::ostream &debug_stream, const std::vector<std::string> &remotes);

nodes_data::ptr start_nodes(std::ostream &debug_stream, const std::vector<config_data> &configs, const std::string &path)
{
	nodes_data::ptr data = std::make_shared<nodes_data>();

	std::string base_path;
	std::string auth_cookie;
	std::string cocaine_config_template = read_file(COCAINE_CONFIG_PATH);
	std::string run_path;

	{
		char buffer[1024];

		snprintf(buffer, sizeof(buffer), "%04x%04x", rand(), rand());
		buffer[sizeof(buffer) - 1] = 0;
		auth_cookie = buffer;

		snprintf(buffer, sizeof(buffer), "/tmp/elliptics-test-run-%04x/", rand());
		buffer[sizeof(buffer) - 1] = 0;
		run_path = buffer;
	}

	const auto ports = generate_ports(configs.size());

	if (path.empty()) {
		char buffer[1024];

		snprintf(buffer, sizeof(buffer), "/tmp/elliptics-test-%04x/", rand());
		buffer[sizeof(buffer) - 1] = 0;
		base_path = buffer;

		create_directory(base_path);
		data->directory = directory_handler(base_path, true);
	} else {
		base_path = path;

		create_directory(base_path);
		data->directory = directory_handler(base_path, false);
	}

	debug_stream << "Set base directory: \"" << base_path << "\"" << std::endl;

	create_directory(run_path);
	data->run_directory = directory_handler(run_path, true);
	debug_stream << "Set cocaine run directory: \"" << run_path << "\"" << std::endl;

	std::string cocaine_remotes;
	for (size_t j = 0; j < configs.size(); ++j) {
		if (j > 0)
			cocaine_remotes += ", ";
		cocaine_remotes += "\"localhost\": " + ports[j];
	}

	const auto cocaine_locator_ports = generate_ports(configs.size());
	// client only needs connection to one (any) locator service
	data->locator_port = std::stoul(cocaine_locator_ports[0]);

	debug_stream << "Starting " << configs.size() << " servers" << std::endl;

	for (size_t i = 0; i < configs.size(); ++i) {
		debug_stream << "Starting server #" << (i + 1) << std::endl;

		const std::string server_path = base_path + "/server-" + boost::lexical_cast<std::string>(i + 1);

		create_directory(server_path);
		create_directory(server_path + "/blob");
		create_directory(server_path + "/history");

		std::string remotes;
		for (size_t j = 0; j < configs.size(); ++j) {
			if (j == i)
				continue;

			remotes += create_remote(ports[j]);
		}

		config_data config = configs[i];
		if (remotes.empty())
			config("remote", NULL_VALUE);
		else
			config("remote", remotes);

		if (config.has_value("srw_config")) {
			create_directory(server_path + "/run");

			const substitute_context cocaine_variables = {
				{ "COCAINE_LOCATOR_PORT", cocaine_locator_ports[i] },
				{ "COCAINE_PLUGINS_PATH", COCAINE_PLUGINS_PATH },
				{ "ELLIPTICS_REMOTES", cocaine_remotes },
				{ "ELLIPTICS_GROUPS", "1" },
				{ "COCAINE_LOG_PATH", server_path + "/cocaine.log" },
				{ "COCAINE_RUN_PATH", run_path }
			};
			create_cocaine_config(server_path + "/cocaine.conf", cocaine_config_template, cocaine_variables);

			config("srw_config", server_path + "/cocaine.conf");
		}

		create_config(config, server_path + "/ioserv.conf")
				("auth_cookie", auth_cookie)
				("log", server_path + "/log.log")
				("addr", create_remote(ports[i]))
				("history", server_path + "/history")
				("data", server_path + "/blob/data")
				;

		server_node server(server_path + "/ioserv.conf", create_remote(ports[i]));

		server.start();
		debug_stream << "Started server #" << (i + 1) << std::endl;

		data->nodes.emplace_back(std::move(server));
	}

	{
		std::vector<std::string> remotes;
		for (size_t i = 0; i < data->nodes.size(); ++i) {
			remotes.push_back(data->nodes[i].remote());
		}

		start_client_nodes(data, debug_stream, remotes);
	}

	return data;
}

#endif // NO_SERVER

static void start_client_nodes(const nodes_data::ptr &data, std::ostream &debug_stream, const std::vector<std::string> &remotes)
{
	(void) debug_stream;

	dnet_config config;
	memset(&config, 0, sizeof(config));

	logger log;
	if (!data->directory.path().empty()) {
		const std::string path = data->directory.path() + "/client.log";
		log = file_logger(path.c_str(), DNET_LOG_DEBUG);
	}

	data->node.reset(new node(log));
	for (size_t i = 0; i < remotes.size(); ++i) {
		data->node->add_remote(remotes[i].c_str());
	}
}

nodes_data::ptr start_nodes(std::ostream &debug_stream, const std::vector<std::string> &remotes, const std::string &path)
{
	if (remotes.empty()) {
		throw std::runtime_error("Remotes list is empty");
	}

	nodes_data::ptr data = std::make_shared<nodes_data>();
	data->directory = directory_handler(path, false);
	start_client_nodes(data, debug_stream, remotes);
	return data;
}

std::string read_file(const char *file_path)
{
	char buffer[1024];
	std::string result;

	std::ifstream config_in(file_path);
	if (!config_in)
		throw std::runtime_error(std::string("can not open file for read: ") + file_path);

	while (config_in) {
		std::streamsize read = config_in.readsome(buffer, sizeof(buffer));
		if (read > 0)
			result.append(buffer, buffer + read);
		else
			break;
	}

	return result;
}

} // namespace tests
