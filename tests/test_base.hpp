#ifndef TEST_BASE_HPP
#define TEST_BASE_HPP

#include <elliptics/cppdef.h>

namespace tests {

using namespace ioremap::elliptics;

#define ELLIPTICS_CHECK_IMPL(R, C, CMD) auto R = (C); \
	R.wait(); \
{ \
	auto base_message = BOOST_TEST_STRINGIZE(C); \
	std::string message(base_message.begin(), base_message.end()); \
	message += ", err: \""; \
	message += R.error().message(); \
	message += "\""; \
	CMD(!R.error(), message); \
}

#define ELLIPTICS_CHECK_ERROR_IMPL(R, C, E, CMD) auto R = (C); \
	R.wait(); \
	if (R.error().code() != (E)) { \
	auto base_message = BOOST_TEST_STRINGIZE(C); \
	std::stringstream out; \
	out << std::string(base_message.begin(), base_message.end()) \
	<< ", expected error: " << (E) << ", received: \"" << R.error().message() << "\""; \
	CMD(false, out.str()); \
}

#define ELLIPTICS_COMPARE_REQUIRE(R, C, D) ELLIPTICS_REQUIRE(R, C); \
	do { \
		auto R ## _result = (R).get_one(); \
		BOOST_REQUIRE_EQUAL((R ## _result).file().to_string(), (D)); \
	} while (0)

#define ELLIPTICS_WARN(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_WARN_MESSAGE)
#define ELLIPTICS_CHECK(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_CHECK_MESSAGE)
#define ELLIPTICS_REQUIRE(R, C) ELLIPTICS_CHECK_IMPL(R, (C), BOOST_REQUIRE_MESSAGE)

#define ELLIPTICS_WARN_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_WARN_MESSAGE)
#define ELLIPTICS_CHECK_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_CHECK_MESSAGE)
#define ELLIPTICS_REQUIRE_ERROR(R, C, E) ELLIPTICS_CHECK_ERROR_IMPL(R, (C), (E), BOOST_REQUIRE_MESSAGE)

#ifdef USE_MASTER_SUITE
#  define ELLIPTICS_TEST_CASE(M, C...) do { framework::master_test_suite().add(BOOST_TEST_CASE(std::bind( M, ##C ))); } while (false)
#else
#  define ELLIPTICS_TEST_CASE(M, C...) do { suite->add(BOOST_TEST_CASE(std::bind( M, ##C ))); } while (false)
#endif

session create_session(node n, std::initializer_list<int> groups, uint64_t cflags, uint32_t ioflags);

class directory_handler
{
public:
	directory_handler();
	directory_handler(const std::string &path, bool remove);
	directory_handler(directory_handler &&other);
	~directory_handler();

	directory_handler &operator= (directory_handler &&other);

	directory_handler(const directory_handler &) = delete;
	directory_handler &operator =(const directory_handler &) = delete;

	std::string path() const;

private:
	std::string m_path;
	bool m_remove;
};

void create_directory(const std::string &path);

#ifndef NO_SERVER

enum dummy_value_type { DUMMY_VALUE, NULL_VALUE };

class config_data
{
public:
	config_data &operator() (const std::string &name, const std::string &value);
	config_data &operator() (const std::string &name, int value);
	config_data &operator() (const std::string &name, dummy_value_type);

	static config_data default_srw_value();
	static config_data default_value();

	bool has_value(const std::string &name) const;

protected:
	std::vector<std::pair<std::string, std::string> >  m_data;
};

class config_data_writer : public config_data
{
public:
	config_data_writer() = delete;
	config_data_writer &operator =(const config_data_writer &other) = delete;

	config_data_writer(const config_data_writer &other);
	config_data_writer(const config_data &other, const std::string &path);

	~config_data_writer();

	template <typename T>
	config_data_writer &operator() (const std::string &name, const T &value)
	{
		config_data::operator ()(name, value);

		return *this;
	}

	void write();

private:
	std::string m_path;
};

class server_node
{
public:
	server_node();
	server_node(const std::string &path, const std::string &remote);
	server_node(server_node &&other);

	server_node &operator =(server_node &&other);

	server_node(const server_node &other) = delete;
	server_node &operator =(const server_node &other) = delete;

	~server_node();

	void start();
	void stop();

	std::string remote() const;
	dnet_node *get_native();

private:
	dnet_node *m_node;
	std::string m_path;
	std::string m_remote;
};

#endif // NO_SERVER

struct nodes_data
{
	typedef std::shared_ptr<nodes_data> ptr;

#ifndef NO_SERVER
	std::vector<server_node> nodes;
	directory_handler directory;
	int locator_port;
#endif // NO_SERVER
	directory_handler run_directory;

	std::unique_ptr<ioremap::elliptics::node> node;
};

#ifndef NO_SERVER

nodes_data::ptr start_nodes(std::ostream &debug_stream, const std::vector<config_data> &configs, const std::string &path);

#endif // NO_SERVER

nodes_data::ptr start_nodes(std::ostream &debug_stream, const std::vector<std::string> &remotes, const std::string &path);

std::string read_file(const char *file_path);

} // namespace tests

#endif // TEST_BASE_HPP
