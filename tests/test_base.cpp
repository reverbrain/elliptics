#include "test_base.hpp"
#include "../example/common.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/version.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>

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

config_data &config_data::operator() (const std::string &name, const std::vector<std::string> &value)
{
	return (*this)(name, variant(value));
}

config_data &config_data::operator()(const std::string &name, const std::string &value)
{
	return (*this)(name, variant(value));
}

config_data &config_data::operator()(const std::string &name, const char *value)
{
	return (*this)(name, std::string(value));
}

config_data &config_data::operator()(const std::string &name, uint64_t value)
{
	return (*this)(name, variant(value));
}

config_data &config_data::operator()(const std::string &name, int value)
{
	return (*this)(name, variant(value));
}

bool config_data::has_value(const std::string &name) const
{
	return value_impl(name);
}

struct stringify_visitor : public boost::static_visitor<std::string>
{
	template <typename T>
	std::string operator() (const T &value) const
	{
		return boost::lexical_cast<std::string>(value);
	}

	std::string operator() (const std::vector<std::string> &) const
	{
		return std::string();
	}
};

std::string config_data::string_value(const std::string &name) const
{
	auto value = value_impl(name);
	return value ? boost::apply_visitor(stringify_visitor(), *value) : std::string();
}

config_data &config_data::operator()(const std::string &name, const config_data::variant &value)
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

const config_data::variant *config_data::value_impl(const std::string &name) const
{
	for (auto it = m_data.begin(); it != m_data.end(); ++it) {
		if (it->first == name) {
			return &it->second;
		}
	}

	return NULL;
}

server_config server_config::default_value()
{
	server_config data;
	data.options
			("join", 1)
			("flags", 4)
			("wait_timeout", 60)
			("check_timeout", 60)
			("io_thread_num", 50)
			("nonblocking_io_thread_num", 16)
			("net_thread_num", 16)
			("indexes_shard_count", 16)
			("daemon", 0)
			("bg_ionice_class", 3)
			("bg_ionice_prio", 0)
			("server_net_prio", 1)
			("client_net_prio", 6)
			("cache_size", 1024 * 1024 * 256)
			("caches_number", 16);
	data.backends.resize(1);
	data.backends[0]
			("type", "blob")
			("sync", 5)
			("blob_flags", 6)
			("iterate_thread_num", 1)
			("blob_size", "10M")
			("records_in_blob", 10000000)
			("defrag_timeout", 3600)
			("defrag_percentage", 25);
	return data;
}

server_config server_config::default_srw_value()
{
	server_config config = default_value();
	config.options("srw_config", "tmp");
	return config;
}

struct json_value_visitor : public boost::static_visitor<>
{
	json_value_visitor(const char *name, rapidjson::Value *object, rapidjson::MemoryPoolAllocator<> *allocator) :
		name(name), object(object), allocator(allocator)
	{
	}

	const char *name;
	rapidjson::Value *object;
	rapidjson::MemoryPoolAllocator<> *allocator;

	void operator() (const std::vector<std::string> &value) const
	{
		rapidjson::Value result;
		result.SetArray();

		for (auto it = value.begin(); it != value.end(); ++it) {
			rapidjson::Value string;
			string.SetString(it->c_str(), it->size(), *allocator);
			result.PushBack(string, *allocator);
		}

		object->AddMember(name, result, *allocator);
	}

	void operator() (const std::string &value) const
	{
		rapidjson::Value result;
		result.SetString(value.c_str(), value.size(), *allocator);
		object->AddMember(name, result, *allocator);
	}

	void operator() (unsigned long long value) const
	{
		rapidjson::Value result;
		result.SetUint64(value);
		object->AddMember(name, result, *allocator);
	}
};

void server_config::write(const std::string &path)
{
	rapidjson::MemoryPoolAllocator<> allocator;
	rapidjson::Value server;
	server.SetObject();

	rapidjson::Value logger;
	logger.SetObject();

	logger.AddMember("type", log_path.c_str(), allocator);
	logger.AddMember("level", DNET_LOG_DEBUG, allocator);

	server.AddMember("loggers", logger, allocator);

	rapidjson::Value options_json;
	options_json.SetObject();

	for (auto it = options.m_data.begin(); it != options.m_data.end(); ++it) {
		json_value_visitor visitor(it->first.c_str(), &options_json, &allocator);
		boost::apply_visitor(visitor, it->second);
	}

	server.AddMember("options", options_json, allocator);

	rapidjson::Value backends_json;
	backends_json.SetArray();

	for (auto it = backends.begin(); it != backends.end(); ++it) {
		rapidjson::Value backend;
		backend.SetObject();

		for (auto jt = it->m_data.begin(); jt != it->m_data.end(); ++jt) {
			json_value_visitor visitor(jt->first.c_str(), &backend, &allocator);
			boost::apply_visitor(visitor, jt->second);
		}

		backends_json.PushBack(backend, allocator);
	}

	server.AddMember("backends", backends_json, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);

	server.Accept(writer);

	std::ofstream out;
	out.open(path.c_str());

	if (!out) {
		throw std::runtime_error("Can not open file \"" + path + "\" for writing");
	}

	out.write(buffer.GetString(), buffer.Size());
	out << std::endl;
}

server_config &server_config::apply_options(const config_data &data)
{
	for (auto it = data.m_data.begin(); it != data.m_data.end(); ++it) {
		options(it->first, it->second);
	}

	return *this;
}

server_node::server_node() : m_node(NULL)
{
}

server_node::server_node(const std::string &path, const std::string &remote, int monitor_port)
	: m_node(NULL), m_path(path), m_remote(remote), m_monitor_port(monitor_port)
{
}

server_node::server_node(server_node &&other) :
	m_node(other.m_node), m_path(std::move(other.m_path)), m_remote(std::move(other.m_remote)), m_monitor_port(other.monitor_port())
{
	other.m_node = NULL;
}

server_node &server_node::operator =(server_node &&other)
{
	std::swap(m_node, other.m_node);
	std::swap(m_path, other.m_path);
	std::swap(m_remote, other.m_remote);
	std::swap(m_monitor_port, other.m_monitor_port);

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
	dnet_server_node_destroy(m_node);
	m_node = NULL;
}

std::string server_node::remote() const
{
	return m_remote;
}

int server_node::monitor_port() const
{
	return m_monitor_port;
}

dnet_node *server_node::get_native()
{
	return m_node;
}

static std::vector<std::string> generate_ports(size_t count, std::set<std::string> &ports)
{
	std::vector<std::string> result;

	while (result.size() < count) {
		// Random port from 10000 to 60000
		int port = 10000 + (rand() % 50000);
		std::string port_str = boost::lexical_cast<std::string>(port);
		if (ports.find(port_str) != ports.end())
			continue;

		result.push_back(port_str);
		ports.insert(port_str);
	}

	return result;
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

nodes_data::ptr start_nodes(std::ostream &debug_stream, const std::vector<server_config> &configs, const std::string &path)
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

	std::set<std::string> all_ports;
	const auto ports = generate_ports(configs.size(), all_ports);
	const auto monitor_ports = generate_ports(configs.size(), all_ports);

	if (path.empty()) {
		char buffer[1024];

		snprintf(buffer, sizeof(buffer), "/tmp/elliptics-test-%04x/", rand());
		buffer[sizeof(buffer) - 1] = 0;
		base_path = buffer;

		create_directory(base_path);
		data->directory = directory_handler(base_path, true);
	} else {
#if BOOST_VERSION >= 104600
		boost::filesystem::path boost_path = boost::filesystem::absolute(path);
#else
		boost::filesystem::path boost_path = boost::filesystem::complete(path, boost::filesystem::current_path());
#endif
		base_path = boost_path.string();

		create_directory(base_path);
		data->directory = directory_handler(base_path, false);
	}

	debug_stream << "Set base directory: \"" << base_path << "\"" << std::endl;

	create_directory(run_path);
	data->run_directory = directory_handler(run_path, true);
	debug_stream << "Set cocaine run directory: \"" << run_path << "\"" << std::endl;

	std::set<std::string> cocaine_unique_groups;
	std::string cocaine_remotes;
	std::string cocaine_groups;
	for (size_t j = 0; j < configs.size(); ++j) {
		if (j > 0)
			cocaine_remotes += ", ";
		cocaine_remotes += "\"localhost:" + ports[j] + ":2\"";
		const std::string group = configs[j].options.string_value("group");
		if (cocaine_unique_groups.find(group) == cocaine_unique_groups.end()) {
			if (!cocaine_groups.empty())
				cocaine_groups += ", ";
			cocaine_groups += group;
		}
	}

	const auto cocaine_locator_ports = generate_ports(configs.size(), all_ports);
	// client only needs connection to one (any) locator service
	data->locator_port = std::stoul(cocaine_locator_ports[0]);

	debug_stream << "Starting " << configs.size() << " servers" << std::endl;

	for (size_t i = 0; i < configs.size(); ++i) {
		debug_stream << "Starting server #" << (i + 1) << std::endl;

		const std::string server_suffix = "/server-" + boost::lexical_cast<std::string>(i + 1);
		const std::string server_path = base_path + server_suffix;

		create_directory(server_path);
		create_directory(server_path + "/blob");
		create_directory(server_path + "/history");

		std::vector<std::string> remotes;
		for (size_t j = 0; j < configs.size(); ++j) {
			if (j == i)
				continue;

			remotes.push_back(create_remote(ports[j]));
		}

		server_config config = configs[i];
		if (!remotes.empty())
			config.options("remote", remotes);

		if (config.options.has_value("srw_config")) {
			const std::string server_run_path = run_path + server_suffix;

			create_directory(server_run_path);

			const substitute_context cocaine_variables = {
				{ "COCAINE_LOCATOR_PORT", cocaine_locator_ports[i] },
				{ "COCAINE_PLUGINS_PATH", COCAINE_PLUGINS_PATH },
				{ "ELLIPTICS_REMOTES", cocaine_remotes },
				{ "ELLIPTICS_GROUPS", cocaine_groups },
				{ "COCAINE_LOG_PATH", server_path + "/cocaine.log" },
				{ "COCAINE_RUN_PATH", server_run_path }
			};
			create_cocaine_config(server_path + "/cocaine.conf", cocaine_config_template, cocaine_variables);

			config.options("srw_config", server_path + "/cocaine.conf");
		}

		if (config.log_path.empty())
			config.log_path = server_path + "/log.log";

		config.options
				("auth_cookie", auth_cookie)
				("address", std::vector<std::string>(1, create_remote(ports[i])))
				("monitor_port", boost::lexical_cast<int>(monitor_ports[i]))
				;

		config.backends[0]
				("history", server_path + "/history")
				("data", server_path + "/blob/data")
				;

		config.write(server_path + "/ioserv.conf");

		server_node server(server_path + "/ioserv.conf",
			create_remote(ports[i]),
			boost::lexical_cast<int>(monitor_ports[i]));

		try {
			server.start();
		} catch (...) {
			std::ifstream in;
			in.open(config.log_path.c_str());

			try {
				if (in) {
					std::string line;
					while (std::getline(in, line))
						debug_stream << line << std::endl;
				}
			} catch (...) {
			}

			throw;
		}

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

nodes_data::~nodes_data()
{
#ifndef NO_SERVER
	for (auto it = nodes.begin(); it != nodes.end(); ++it)
		dnet_set_need_exit(it->get_native());
#endif // NO_SERVER
}

} // namespace tests
