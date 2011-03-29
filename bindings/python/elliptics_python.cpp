/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <boost/python.hpp>

#if 0

using namespace boost::python;

#include <iostream>
#include <fstream>

class test_class_base {
	public:
		test_class_base(int mask = 0xff) : mask(mask) {};
		virtual ~test_class_base() {};
		
		virtual void log(const char *msg) = 0;

		int get_mask(void) {return mask;};
	private:
		int mask;
};

class test_class : public test_class_base {
	public:
		test_class(const char *path);
		virtual ~test_class();

		virtual void log(const char *msg);
		unsigned char test(unsigned long lptr) { unsigned char *ptr = (unsigned char *)lptr; return ptr[0]; };
	private:
		std::ofstream *stream;
};

test_class::test_class(const char *path)
{
	stream = new std::ofstream(path);
}

test_class::~test_class()
{
	delete stream;
}

void test_class::log(const char *msg)
{
	(*stream) << std::hex << get_mask() << ": " << msg;
	//(*stream) << msg;
	stream->flush();
}

class test_class_base_wrap : public test_class_base, public wrapper<test_class_base> {
	public:
		test_class_base_wrap(int mask) : test_class_base(mask) {};
		virtual ~test_class_base_wrap() {};

		void log(const char *msg) {
			this->get_override("log")(msg);
		}
};

class test_class_wrap : public test_class, public wrapper<test_class> {
	public:
		test_class_wrap(const char *msg) : test_class(msg) {};
		virtual ~test_class_wrap() {} ;

		void log(const char *msg) {
			if (override log = this->get_override("log")) {
				log(msg); // *note*
				return;
			}

			test_class::log(msg);
		}

		void default_log(const char *msg) { this->test_class::log(msg); }
};


BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<test_class_base_wrap, boost::noncopyable>("test_class_base", init<int>())
		.def("get_mask", &test_class_base::get_mask)
		.def("log", pure_virtual(&test_class_base::log))
	;

	class_<test_class_wrap, boost::noncopyable, bases<test_class_base> >("test_class", init<const char *>())
		.def("log", &test_class::log, &test_class_wrap::default_log)
		.def("test", &test_class::test)
	;
};

#else
#include "elliptics/cppdef.h"

using namespace boost::python;

struct elliptics_id {
	list		id;
	uint32_t	group_id;
	uint32_t	version;
};

static void elliptics_extract_id(const struct elliptics_id &e, struct dnet_id &id)
{
	int length = len(e.id);

	memset(id.id, 0, sizeof(id.id));

	if (length > sizeof(id.id))
		length = sizeof(id.id);

	for (int i=0; i<length; ++i)
		id.id[i] = extract<uint8_t>(e.id[i]);

	id.group_id = e.group_id;
	id.version = e.version;
}

class elliptics_log_wrap : public elliptics_log, public wrapper<elliptics_log> {
	public:
		elliptics_log_wrap(const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) : elliptics_log(mask) {};

		void log(const uint32_t mask, const char *msg) {
			this->get_override("log")(mask, msg);
		}

		unsigned long clone(void) {
			return this->get_override("clone")();
		}
};

class elliptics_log_file_wrap : public elliptics_log_file, public wrapper<elliptics_log_file> {
	public:
		elliptics_log_file_wrap(const char *file, const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) :
			elliptics_log_file(file, mask) {};

		void log(const uint32_t mask, const char *msg) {
			if (override log = this->get_override("log")) {
				log(mask, msg);
				return;
			}

			elliptics_log_file::log(mask, msg);
		}

		void default_log(uint32_t mask, const char *msg) { this->elliptics_log_file::log(mask, msg); }

		unsigned long clone(void) {
			if (override clone = this->get_override("clone"))
				return clone();

			return elliptics_log_file::clone();
		}

		unsigned long default_clone(void) { return this->elliptics_log_file::clone(); }
};

class elliptics_node_python : public elliptics_node {
	public:
		elliptics_node_python(elliptics_log &l) : elliptics_node(l) {}

		void add_groups(const list &pgroups) {
			std::vector<int> groups;

			for (int i=0; i<len(pgroups); ++i)
				groups.push_back(extract<int>(pgroups[i]));

			elliptics_node::add_groups(groups);
		}

		void write_metadata(const struct elliptics_id &id, const std::string &remote, const list &pgroups) {
			struct dnet_id raw;
			elliptics_extract_id(id, raw);

			std::vector<int> groups;

			for (int i=0; i<len(pgroups); ++i)
				groups.push_back(extract<int>(pgroups[i]));

			elliptics_node::write_metadata((const dnet_id&)raw, remote, groups);
		}

		void read_file_by_id(struct elliptics_id &id, const char *file, uint64_t offset, uint64_t size) {
			struct dnet_id raw;
			elliptics_extract_id(id, raw);
			elliptics_node::read_file(raw, const_cast<char *>(file), offset, size);
		}

		void read_file_by_data_transform(const std::string &remote, const char *file, uint64_t offset, uint64_t size) {
			elliptics_node::read_file((std::string &)remote, const_cast<char *>(file), offset, size);
		}

		void write_file_by_id(struct elliptics_id &id, const char *file, uint64_t local_offset, uint64_t offset, uint64_t size,
				unsigned int aflags = 0, unsigned int ioflags = 0) {
			struct dnet_id raw;
			elliptics_extract_id(id, raw);
			elliptics_node::write_file(raw, const_cast<char *>(file), local_offset, offset, size, aflags, ioflags);
		}

		void write_file_by_data_transform(const std::string &remote, const char *file, uint64_t local_offset,
				uint64_t offset, uint64_t size, unsigned int aflags = 0, unsigned int ioflags = 0) {
			elliptics_node::write_file((std::string &)remote, const_cast<char *>(file), local_offset, offset, size, aflags, ioflags);
		}

		std::string read_data_by_id(const struct elliptics_id &id, uint64_t size) {
			struct dnet_id raw;
			elliptics_extract_id(id, raw);
			return elliptics_node::read_data_wait(raw, size);
		}

		std::string read_data_by_data_transform(const std::string &remote, uint64_t size) {
			return elliptics_node::read_data_wait((std::string &)remote, size);
		}

		int write_data_by_id(const struct elliptics_id &id, const std::string &data,
							unsigned int aflags = DNET_ATTR_DIRECT_TRANSACTION,
							unsigned int ioflags = DNET_IO_FLAGS_NO_HISTORY_UPDATE) {
			struct dnet_id raw;
			elliptics_extract_id(id, raw);
			return elliptics_node::write_data_wait(raw, (std::string &)data, aflags, ioflags);
		}

		int write_data_by_data_transform(const std::string &remote, const std::string &data,
							unsigned int aflags = DNET_ATTR_DIRECT_TRANSACTION,
							unsigned int ioflags = DNET_IO_FLAGS_NO_HISTORY_UPDATE) {
			return elliptics_node::write_data_wait((std::string &)remote, (std::string &)data, aflags, ioflags);
		}
};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(add_remote_overloads, add_remote, 2, 3);
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_id_overloads, write_file_by_id, 5, 7);
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_data_transform_overloads, write_file_by_data_transform, 5, 7);
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_data_by_id_overloads, write_data_by_id, 2, 4);
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_data_by_data_transform_overloads, write_data_by_data_transform, 2, 4);

BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<elliptics_id>("elliptics_id")
		.def_readwrite("id", &elliptics_id::id)
		.def_readwrite("group_id", &elliptics_id::group_id)
		.def_readwrite("version", &elliptics_id::version)
	;

	class_<elliptics_log_wrap, boost::noncopyable>("elliptics_log", init<const uint32_t>())
		.def("log", pure_virtual(&elliptics_log::log))
		.def("clone", pure_virtual(&elliptics_log::clone))
	;

	class_<elliptics_log_file_wrap, boost::noncopyable, bases<elliptics_log> >("elliptics_log_file", init<const char *, const uint32_t>())
		.def("log", &elliptics_log_file::log, &elliptics_log_file_wrap::default_log)
		.def("clone", &elliptics_log_file::clone, &elliptics_log_file_wrap::default_clone)
	;

	class_<elliptics_node>("elliptics_node", init<elliptics_log &>())
		.def("add_remote", &elliptics_node::add_remote, add_remote_overloads())
	;

	class_<elliptics_node_python, bases<elliptics_node> >("elliptics_node_python", init<elliptics_log &>())
		.def("add_remote", &elliptics_node::add_remote, add_remote_overloads())

		.def("add_groups", &elliptics_node_python::add_groups)

		.def("read_file", &elliptics_node_python::read_file_by_id)
		.def("read_file", &elliptics_node_python::read_file_by_data_transform)
		.def("write_file", &elliptics_node_python::write_file_by_id, write_file_by_id_overloads())
		.def("write_file", &elliptics_node_python::write_file_by_data_transform, write_file_by_data_transform_overloads())

		.def("read_data", &elliptics_node_python::read_data_by_id)
		.def("read_data", &elliptics_node_python::read_data_by_data_transform)
		.def("write_data", &elliptics_node_python::write_data_by_id, write_data_by_id_overloads())
		.def("write_data", &elliptics_node_python::write_data_by_data_transform, write_data_by_data_transform_overloads())

		.def("lookup_addr", &elliptics_node::lookup_addr)
		.def("write_metadata", &elliptics_node_python::write_metadata)
	;
};
#endif
