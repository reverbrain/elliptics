#ifndef SRW_TEST_HPP
#define SRW_TEST_HPP

#include <cocaine/framework/services/storage.hpp>
#include <msgpack.hpp>
#include "test_base.hpp"

#ifndef BOOST_REQUIRE_EQUAL
# define BOOST_REQUIRE_EQUAL(a, b) do { \
		if ((a) != (b)) { \
			std::stringstream error_stream; \
			error_stream << "error occured at function: " << __PRETTY_FUNCTION__ << ", line: " << __LINE__ << #a << " != " << #b; \
			throw std::runtime_error(error_stream.str()); \
		} \
	} while (false)

# undef ELLIPTICS_REQUIRE
# define ELLIPTICS_REQUIRE(result, command) \
	auto result = (command); \
	result.wait(); \
	result.error().throw_error();
#endif

namespace tests {

struct node_info
{
	std::string path;
	std::vector<std::string> remotes;
	std::vector<int> groups;

#ifndef NO_UPPLOAD_APPLICATION
	static node_info create(nodes_data &data)
	{
		node_info info;

		info.groups = { 1 };
		info.path = data.directory.path();
		for (auto it = data.nodes.begin(); it != data.nodes.end(); ++it)
			info.remotes.push_back(it->remote());

		return info;
	}
#endif

	void unpack(const std::string &data)
	{
		msgpack::unpacked msg;
		msgpack::unpack(&msg, data.c_str(), data.size());
		msgpack::object &obj = msg.get();

		if (obj.type != msgpack::type::ARRAY || obj.via.array.size != 3)
			throw msgpack::type_error();

		obj.via.array.ptr[0].convert(&remotes);
		obj.via.array.ptr[1].convert(&groups);
		obj.via.array.ptr[2].convert(&path);
	}

	std::string pack()
	{
		msgpack::sbuffer buffer;
		msgpack::packer<msgpack::sbuffer> packer(buffer);

		packer.pack_array(3);
		packer << remotes;
		packer << groups;
		packer << path;

		return std::string(buffer.data(), buffer.size());
	}
};

#ifndef NO_UPPLOAD_APPLICATION
static std::string application_name()
{
	return "dnet_cpp_srw_test_app";
}

static dnet_id generate_id(session &sess, const std::string &name)
{
	key key_id = name;
	key_id.transform(sess);
	return key_id.id();
}

static void start_application(session &sess, const std::string &app_name)
{
	dnet_id id = generate_id(sess, app_name);

	ELLIPTICS_REQUIRE(result, sess.exec(&id, app_name + "@start-task", data_pointer()));
}

static void init_application_impl(session &sess, const std::string &app_name, nodes_data &data)
{
	dnet_id id = generate_id(sess, app_name);
	node_info info = node_info::create(data);

	ELLIPTICS_REQUIRE(exec_result, sess.exec(&id, app_name + "@init", info.pack()));

	sync_exec_result result = exec_result;
	BOOST_REQUIRE_EQUAL(result.size(), 1);
	BOOST_REQUIRE_EQUAL(result[0].context().data().to_string(), "inited");
}

static void upload_application(int locator_port, const std::string &path)
{
	using namespace cocaine::framework;

	const std::string app_name = application_name();

	service_manager_t::endpoint_t endpoint("127.0.0.1", locator_port);
	auto manager = service_manager_t::create(endpoint);

	auto storage = manager->get_service<storage_service_t>("storage");

	const std::vector<std::string> app_tags = {
		"apps"
	};
	const std::vector<std::string> profile_tags = {
		"profiles"
	};

	msgpack::sbuffer buffer;
	{
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer.pack_map(1);
		packer << std::string("isolate");
		packer.pack_map(2);
		packer << std::string("type");
		packer << std::string("process");
		packer << std::string("args");
		packer.pack_map(1);
		packer << std::string("spool");
		packer << path;
	}
	std::string profile(buffer.data(), buffer.size());
	{
		buffer.clear();
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer.pack_map(2);
		packer << std::string("type");
		packer << std::string("binary");
		packer << std::string("slave");
		packer << app_name;
	}
	std::string manifest(buffer.data(), buffer.size());
	{
		buffer.clear();
		msgpack::packer<msgpack::sbuffer> packer(buffer);
		packer << read_file(COCAINE_TEST_APP);
	}
	std::string app(buffer.data(), buffer.size());

	storage->write("manifests", app_name, manifest, app_tags).next();
	storage->write("profiles", app_name, profile, profile_tags).next();
	storage->write("apps", app_name, app, profile_tags).next();
}
#endif

} // namespace tests

#endif // SRW_TEST_HPP
