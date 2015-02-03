#define TEST_DO_NOT_INCLUDE_PLACEHOLDERS

#include "test_base.hpp"
#include "../example/common.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/version.hpp>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>

#include <fstream>
#include <iostream>
#include <set>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>

#ifdef HAVE_COCAINE
#  include <cocaine/framework/services/storage.hpp>
#endif

namespace tests {

static std::string cocaine_config_path()
{
	char *result = getenv("TEST_COCAINE_CONFIG");
	if (!result)
		throw std::runtime_error("TEST_COCAINE_CONFIG environment variable is no set");

	return result;
}

static std::string cocaine_config_plugins()
{
	char *result = getenv("TEST_COCAINE_PLUGINS");
	if (!result)
		throw std::runtime_error("TEST_COCAINE_PLUGINS environment variable is no set");

	return result;
}

static const char *ioserv_path()
{
	char *result = getenv("TEST_IOSERV_PATH");
	if (!result)
		return "/usr/bin/dnet_ioserv";

	return result;
}

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

config_data &config_data::operator()(const std::string &name, int64_t value)
{
	return (*this)(name, variant(value));
}

config_data &config_data::operator()(const std::string &name, int value)
{
	return (*this)(name, variant(int64_t(value)));
}

config_data &config_data::operator()(const std::string &name, bool value)
{
	return (*this)(name, variant(value));
}

config_data &config_data::operator()(const std::string &name, const config_data &value)
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

	std::string operator() (const std::vector<std::string> &) const {
		return std::string();
	}

	std::string operator() (const config_data &) const {
		return std::string();
	}
};

std::string config_data::string_value(const std::string &name) const
{
	auto value = value_impl(name);
	return value ? boost::apply_visitor(stringify_visitor(), *value) : std::string();
}

config_data::const_iterator config_data::cbegin() const
{
	return m_data.cbegin();
}

config_data::const_iterator config_data::cend() const
{
	return m_data.cend();
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
			("join", true)
			("flags", 4)
			("wait_timeout", 60)
			("check_timeout", 60)
			("io_thread_num", 2)
			("nonblocking_io_thread_num", 2)
			("net_thread_num", 1)
			("indexes_shard_count", 16)
			("daemon", false)
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

	void operator() (const config_data &value) const
	{
		rapidjson::Value result;
		result.SetObject();

		for (auto it = value.cbegin(); it != value.cend(); ++it) {
			json_value_visitor visitor(it->first.c_str(), &result, allocator);
			boost::apply_visitor(visitor, it->second);
		}

		object->AddMember(name, result, *allocator);
	}

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

	void operator() (bool value) const
	{
		rapidjson::Value result;
		result.SetBool(value);
		object->AddMember(name, result, *allocator);
	}

	void operator() (int64_t value) const
	{
		rapidjson::Value result;
		result.SetUint64(value);
		object->AddMember(name, result, *allocator);
	}
};

void server_config::write(const std::string &path)
{
	const std::string format = file_logger::format();

	rapidjson::MemoryPoolAllocator<> allocator;

	rapidjson::Value formatter;
	formatter.SetObject();
	formatter.AddMember("type", "string", allocator);
	formatter.AddMember("pattern", format.c_str(), allocator);

	rapidjson::Value sink;
	sink.SetObject();
	sink.AddMember("type", "files", allocator);
	sink.AddMember("path", log_path.c_str(), allocator);
	sink.AddMember("autoflush", true, allocator);

	rapidjson::Value rotation;
	rotation.SetObject();
	rotation.AddMember("move", 0, allocator);
	sink.AddMember("rotation", rotation, allocator);

	rapidjson::Value frontend;
	frontend.SetObject();
	frontend.AddMember("formatter", formatter, allocator);
	frontend.AddMember("sink", sink, allocator);

	rapidjson::Value frontends;
	frontends.SetArray();
	frontends.PushBack(frontend, allocator);

	rapidjson::Value log_level(file_logger::generate_level(DNET_LOG_DEBUG).c_str(), allocator);

	rapidjson::Value logger;
	logger.SetObject();
	logger.AddMember("level", log_level, allocator);
	logger.AddMember("frontends", frontends, allocator);

	rapidjson::Value server;
	server.SetObject();
	server.AddMember("logger", logger, allocator);

	rapidjson::Value options_json;
	options_json.SetObject();

	rapidjson::Value cache_json;
	cache_json.SetNull();

	rapidjson::Value monitor_json;
	monitor_json.SetNull();

	for (auto it = options.m_data.begin(); it != options.m_data.end(); ++it) {
		rapidjson::Value *object = &options_json;
		const char *key = it->first.c_str();

		if (it->first.compare(0, 6, "cache_") == 0) {
			if (!cache_json.IsObject())
				cache_json.SetObject();
			key = it->first.c_str() + 6;
			object = &cache_json;
		} else if (it->first.compare(0, 8, "monitor_") == 0) {
			if (!monitor_json.IsObject())
				monitor_json.SetObject();
			key = it->first.c_str() + 8;
			object = &monitor_json;
		}

		json_value_visitor visitor(key, object, &allocator);
		boost::apply_visitor(visitor, it->second);
	}

	options_json.AddMember("cache", cache_json, allocator);
	options_json.AddMember("monitor", monitor_json, allocator);
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
		if (it->first == "group")
			backends.front()(it->first, it->second);
		else
			options(it->first, it->second);
	}

	return *this;
}

server_node::server_node() : m_node(NULL), m_monitor_port(0), m_fork(false), m_kill_sent(false), m_pid(0)
{
}

server_node::server_node(const std::string &path, const server_config &config, const address &remote, int monitor_port, bool fork)
	: m_node(NULL), m_path(path), m_config(config), m_remote(remote), m_monitor_port(monitor_port), m_fork(fork), m_kill_sent(false), m_pid(0)
{
}

server_node::server_node(server_node &&other) :
	m_node(other.m_node), m_path(std::move(other.m_path)), m_config(std::move(other.m_config)), m_remote(std::move(other.m_remote)),
	m_monitor_port(other.monitor_port()), m_fork(other.m_fork), m_kill_sent(other.m_kill_sent), m_pid(other.m_pid)
{
	other.m_node = NULL;
	other.m_fork = false;
	other.m_kill_sent = false;
	other.m_pid = 0;
}

server_node &server_node::operator =(server_node &&other)
{
	std::swap(m_node, other.m_node);
	std::swap(m_path, other.m_path);
	std::swap(m_remote, other.m_remote);
	std::swap(m_monitor_port, other.m_monitor_port);
	std::swap(m_fork, other.m_fork);
	std::swap(m_kill_sent, other.m_kill_sent);
	std::swap(m_pid, other.m_pid);

	return *this;
}

server_node::~server_node()
{
	if (is_started()) {
		stop();
		wait_to_stop();
	}
}

void server_node::start()
{
	if (is_started())
		throw std::runtime_error("Server node \"" + m_path + "\" is already started");

	if (m_fork) {
		m_kill_sent = false;
		m_pid = fork();
		if (m_pid == -1) {
			m_pid = 0;
			int err = -errno;
			throw_error(err, "Failed to fork process");
		} else if (m_pid == 0) {
			char buffer[3][1024] = {
				" ",
				"-c"
			};
			std::string ios_path = ioserv_path();
			char * const args[] = {
				const_cast<char*>(ios_path.c_str()),
				buffer[1],
				const_cast<char*>(m_path.c_str()),
				NULL
			};
			auto ld_path = std::string("LD_LIBRARY_PATH=") + getenv("LD_LIBRARY_PATH");
			char * const env[] = {
				const_cast<char*>(ld_path.c_str()),
				NULL
			};
			if (execve(ios_path.data(), args, env) == -1) {
				int err = -errno;
				std::cerr << create_error(err, "Failed to start process \"%s\"", ios_path.c_str()).message() << std::endl;
				quick_exit(1);
			}
		}
	} else {
		m_node = dnet_parse_config(m_path.c_str(), 0);
	}

	if (!is_started())
		throw std::runtime_error("Can not start server with config file: \"" + m_path + "\"");
}

void server_node::stop()
{
	if (!is_started())
		throw std::runtime_error("Server node \"" + m_path + "\" is already stoped");

	if (m_fork) {
		if (!m_kill_sent) {
			m_kill_sent = true;
			kill(m_pid, SIGTERM);
		}
	} else {
		dnet_set_need_exit(m_node);
	}
}

void server_node::wait_to_stop()
{
	if (m_fork) {
		int result;
		waitpid(m_pid, &result, 0);
		m_pid = 0;
	} else if (m_node) {
		dnet_server_node_destroy(m_node);
		m_node = NULL;
	}
}

bool server_node::is_started() const
{
	return !is_stopped();
}

bool server_node::is_stopped() const
{
	if (!m_fork)
		return !m_node;

	if (m_pid) {
		int result;
		int err = waitpid(m_pid, &result, WNOHANG);
		if (err == 0) {
			return false;
		} else if (err == -1) {
			err = -errno;
			throw_error(err, "Failed to check status of pid: %d", int(m_pid));
		}

		m_pid = 0;
	}

	return true;
}

std::string server_node::config_path() const
{
	return m_path;
}

server_config server_node::config() const
{
	return m_config;
}

address server_node::remote() const
{
	return m_remote;
}

int server_node::monitor_port() const
{
	return m_monitor_port;
}

pid_t server_node::pid() const
{
	return m_pid;
}

dnet_node *server_node::get_native()
{
	return m_node;
}

static bool is_bindable(int port)
{
	const int family = AF_INET;
	int s = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (s < 0) {
		int err = -errno;
		throw std::runtime_error("Failed to create socket for family: "
			+ boost::lexical_cast<std::string>(family)
			+ ", err: "
			+ ::strerror(-err)
			+ ", "
			+ boost::lexical_cast<std::string>(err));
	}

	dnet_addr addr;
	addr.addr_len = sizeof(addr.addr);
	addr.family = family;

	int err = dnet_fill_addr(&addr, "127.0.0.1", port, SOCK_STREAM, IPPROTO_TCP);

	if (err) {
		::close(s);
		throw std::runtime_error(std::string("Failed to parse address: ") + strerror(-err)
			+ ", " + boost::lexical_cast<std::string>(err));
	}

	int salen = addr.addr_len;
	struct sockaddr *sa = reinterpret_cast<struct sockaddr *>(addr.addr);

	err = 0;
	::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &err, 4);
	err = ::bind(s, sa, salen);
	::close(s);

	return (err == 0);
}

static std::vector<std::string> generate_ports(size_t count, std::set<std::string> &ports)
{
	std::vector<std::pair<int, int>> ranges;
	const int first_valid = 1025;
	const int last_valid = 65535;

	std::ifstream range("/proc/sys/net/ipv4/ip_local_port_range");
	if (range) {
		int first_invalid = 0;
		int last_invalid = 0;
		range >> first_invalid >> last_invalid;

		first_invalid = std::max(first_invalid, first_valid);
		last_invalid = std::min(last_invalid, last_valid);

		if (first_invalid > first_valid)
			ranges.emplace_back(first_valid, first_invalid - 1);
		if (last_invalid < last_valid)
			ranges.emplace_back(last_invalid + 1, last_valid);
	} else {
		ranges.emplace_back(first_valid, last_valid);
	}

	int ranges_sum = 0;
	for (auto it = ranges.begin(); it != ranges.end(); ++it) {
		ranges_sum += it->second - it->first + 1;
	}

	if (ranges_sum == 0)
		throw std::runtime_error("Failed to find enough count of bindable ports for elliptics servers");

	std::vector<std::string> result;

	size_t bind_errors_count = 0;

	while (result.size() < count) {
		// Choose one random port from available ranges
		int tmp = rand() % ranges_sum;
		int port = 0;
		for (auto it = ranges.begin(); it != ranges.end(); ++it) {
			if (tmp >= it->second - it->first + 1) {
				tmp -= it->second - it->first + 1;
			} else {
				port = it->first + tmp;
				break;
			}
		}

		std::string port_str = boost::lexical_cast<std::string>(port);
		if (ports.find(port_str) != ports.end())
			continue;

		if (!is_bindable(port)) {
			if (++bind_errors_count >= 10) {
				throw std::runtime_error("Failed to find enough count of bindable ports for elliptics servers");
			}
			continue;
		}

		result.push_back(port_str);
		ports.insert(port_str);
		bind_errors_count = 0;
	}

	return result;
}

static std::string create_remote(const std::string &port)
{
	return "127.0.0.1:" + port + ":2";
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

start_nodes_config::start_nodes_config(std::ostream &debug_stream, const std::vector<server_config> &&configs, const std::string &path)
: debug_stream(debug_stream)
, configs(std::move(configs))
, path(path)
, fork(false)
, monitor(true)
, isolated(false)
{}

nodes_data::ptr start_nodes(start_nodes_config &start_config) {
	nodes_data::ptr data = std::make_shared<nodes_data>();

	std::string base_path;
	std::string auth_cookie;
	std::string cocaine_config_template;
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
	const auto ports = generate_ports(start_config.configs.size(), all_ports);
	const auto monitor_ports = start_config.monitor
		? generate_ports(start_config.configs.size(), all_ports)
		: std::vector<std::string>(start_config.configs.size(), "0");

	if (start_config.path.empty()) {
		char buffer[1024];

		snprintf(buffer, sizeof(buffer), "/tmp/elliptics-test-%04x/", rand());
		buffer[sizeof(buffer) - 1] = 0;
		base_path = buffer;

		create_directory(base_path);
		data->directory = directory_handler(base_path, true);
	} else {
#if BOOST_VERSION >= 104600
		boost::filesystem::path boost_path = boost::filesystem::absolute(start_config.path);
#else
		boost::filesystem::path boost_path = boost::filesystem::complete(start_config.path, boost::filesystem::current_path());
#endif
		base_path = boost_path.string();

		create_directory(base_path);
		data->directory = directory_handler(base_path, false);
	}

	start_config.debug_stream << "Set base directory: \"" << base_path << "\"" << std::endl;

	create_directory(run_path);
	data->run_directory = directory_handler(run_path, true);
	start_config.debug_stream << "Set cocaine run directory: \"" << run_path << "\"" << std::endl;

	std::set<std::string> cocaine_unique_groups;
	std::string cocaine_remotes;
	std::string cocaine_groups;
	for (size_t j = 0; j < start_config.configs.size(); ++j) {
		if (j > 0)
			cocaine_remotes += ", ";
		cocaine_remotes += "\"127.0.0.1:" + ports[j] + ":2\"";
		for (auto it = start_config.configs[j].backends.begin(); it != start_config.configs[j].backends.end(); ++it) {
			const std::string group = it->string_value("group");
			if (cocaine_unique_groups.insert(group).second) {
				if (!cocaine_groups.empty())
					cocaine_groups += ", ";
				cocaine_groups += group;
			}
		}
	}

	const auto cocaine_locator_ports = generate_ports(start_config.configs.size(), all_ports);

	std::vector<int> locator_ports;

	start_config.debug_stream << "Starting " << start_config.configs.size() << " servers" << std::endl;

	for (size_t i = 0; i < start_config.configs.size(); ++i) {
		start_config.debug_stream << "Starting server #" << (i + 1) << std::endl;
		server_config config = start_config.configs[i];

		const std::string server_suffix = "/server-" + boost::lexical_cast<std::string>(i + 1);
		const std::string server_path = base_path + server_suffix;

		create_directory(server_path);

		for (size_t j = 0; j < config.backends.size(); ++j) {
			std::string prefix = server_path + "/" + boost::lexical_cast<std::string>(j);
			create_directory(prefix);
			create_directory(prefix + "/history");
			create_directory(prefix + "/blob");
		}

		std::vector<std::string> remotes;
		for (size_t j = 0; j < start_config.configs.size(); ++j) {
			if (j == i)
				continue;

			remotes.push_back(create_remote(ports[j]));
		}

		if (!remotes.empty() && !start_config.isolated)
			config.options("remote", remotes);

		if (config.options.has_value("srw_config")) {
			const std::string server_run_path = run_path + server_suffix;

			if (cocaine_config_template.empty())
				cocaine_config_template = read_file(cocaine_config_path().c_str());

			create_directory(server_run_path);

			// client only needs connection to one (any) locator service
			if (!data->locator_port)
				data->locator_port = boost::lexical_cast<int>(cocaine_locator_ports[i]);

			locator_ports.push_back(boost::lexical_cast<int>(cocaine_locator_ports[i]));

			const substitute_context cocaine_variables = {
				{ "COCAINE_LOCATOR_PORT", cocaine_locator_ports[i] },
				{ "COCAINE_PLUGINS_PATH", cocaine_config_plugins() },
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

		if (start_config.monitor) {
			config_data top_params = config_data()
				("top_k", start_config.top_k)
				("events_limit", start_config.top_events_limit)
				("period_in_seconds", start_config.top_period);
			config.options("monitor_top", top_params);
		}

		for (size_t i = 0; i < config.backends.size(); ++i) {
			std::string prefix = server_path + "/" + boost::lexical_cast<std::string>(i);
			config.backends[i]
					("history", prefix + "/history")
					("data", prefix + "/blob")
					;

			if (!config.backends[i].has_value("backend_id"))
				config.backends[i]("backend_id", static_cast<int64_t>(i));
		}

		config.write(server_path + "/ioserv.conf");

		server_node server(server_path + "/ioserv.conf",
			config,
			create_remote(ports[i]),
			boost::lexical_cast<int>(monitor_ports[i]),
			start_config.fork);

		try {
			server.start();
		} catch (...) {
			std::ifstream in;
			in.open(config.log_path.c_str());

			try {
				if (in) {
					std::string line;
					while (std::getline(in, line))
						start_config.debug_stream << line << std::endl;
				}
			} catch (...) {
			}

			throw;
		}

		start_config.debug_stream << "Started server #" << (i + 1) << std::endl;

		data->nodes.emplace_back(std::move(server));
	}

	for (;;) {
		sleep(1);

		for (size_t i = 0; i < data->nodes.size(); ++i) {
			if (data->nodes[i].is_stopped()) {
				start_config.debug_stream << "Failed to start server #" << (i + 1) << std::endl;
				throw std::runtime_error("Failed to configure servers");
			}
		}

#ifdef HAVE_COCAINE
		bool any_failed = false;

		for (size_t i = 0; i < locator_ports.size(); ++i) {
			try {
				using namespace cocaine::framework;

				service_manager_t::endpoint_t endpoint("127.0.0.1", locator_ports[i]);
				auto manager = service_manager_t::create(endpoint);
				auto storage = manager->get_service<storage_service_t>("storage");
				(void) storage;

				start_config.debug_stream << "Succesfully connected to Cocaine #" << (i + 1) << std::endl;
			} catch (std::exception &) {
				any_failed = true;
				break;
			}
		}

		if (any_failed) {
			start_config.debug_stream << "Cocaine has not been started yet, try again in 1 second" << std::endl;
			continue;
		}
#endif
		break;
	}

	try {
		std::vector<std::string> remotes;
		for (size_t i = 0; i < data->nodes.size(); ++i) {
			remotes.push_back(data->nodes[i].remote().to_string_with_family());
		}

		start_client_nodes(data, start_config.debug_stream, remotes);
	} catch (std::exception &e) {
		start_config.debug_stream << "Failed to connect to servers: " << e.what() << std::endl;
		throw;
	}

	start_config.debug_stream << "Started servers" << std::endl;

	return data;
}

#endif // NO_SERVER

static void start_client_nodes(const nodes_data::ptr &data, std::ostream &debug_stream, const std::vector<std::string> &remotes)
{
	(void) debug_stream;

	dnet_config config;
	memset(&config, 0, sizeof(config));

	data->logger.reset(new logger_base);
	if (!data->directory.path().empty()) {
		const std::string path = data->directory.path() + "/client.log";
		data->logger.reset(new file_logger(path.c_str(), DNET_LOG_DEBUG));
	}

	data->node.reset(new node(logger(*data->logger, blackhole::log::attributes_t())));
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
	for (auto it = nodes.begin(); it != nodes.end(); ++it) {
		if (!it->is_stopped())
			it->stop();
	}
#endif // NO_SERVER
}

} // namespace tests
