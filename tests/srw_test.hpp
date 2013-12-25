#ifndef SRW_TEST_HPP
#define SRW_TEST_HPP

#include <msgpack.hpp>

namespace tests {

struct node_info
{
	std::string path;
	std::vector<std::string> remotes;
	std::vector<int> groups;

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


} // namespace tests

#endif // SRW_TEST_HPP
