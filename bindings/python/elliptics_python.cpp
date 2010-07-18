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

struct dnet_node;

class elliptics_log_wrap : public elliptics_log, public wrapper<elliptics_log> {
	public:
		elliptics_log_wrap(const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) : elliptics_log(mask) {};
		virtual ~elliptics_log_wrap() {};

		void log(const uint32_t mask, const char *msg) {
			this->get_override("log")(mask, msg);
		}
};

class elliptics_log_file_wrap : public elliptics_log_file, public wrapper<elliptics_log_file> {
	public:
		elliptics_log_file_wrap(const char *file, const uint32_t mask = DNET_LOG_ERROR | DNET_LOG_INFO) :
			elliptics_log_file(file, mask) {};
		virtual ~elliptics_log_file_wrap() {};

		void log(const uint32_t mask, const char *msg) {
			if (override log = this->get_override("log")) {
				log(mask, msg); // *note*
				return;
			}

			elliptics_log_file::log(mask, msg);
		}

		void default_log(uint32_t mask, const char *msg) { this->elliptics_log_file::log(mask, msg); }
};

class elliptics_transform_wrap : public elliptics_transform, public wrapper<elliptics_transform> {
	public:
		elliptics_transform_wrap(const char *name) : elliptics_transform(name) {};
		virtual ~elliptics_transform_wrap() {};

		int transform(void *priv, void *src, uint64_t size, void *dst, unsigned int *dsize, unsigned int flags) {
			this->get_override("transform")(priv, src, size, dst, dsize, flags);
		};

		void cleanup(void *priv) {
			this->get_override("cleanup")(priv);
		};
};

class elliptics_transform_openssl_wrap : public elliptics_transform_openssl, public wrapper<elliptics_transform_openssl> {
	public:
		elliptics_transform_openssl_wrap(const char *name) : elliptics_transform_openssl(name) {};
		virtual ~elliptics_transform_openssl_wrap() {};

		int transform(void *priv, void *src, uint64_t size, void *dst, unsigned int *dsize, unsigned int flags) {
			if (override transform = this->get_override("transform"))
				return transform(priv, src, size, dst, dsize, flags);

			elliptics_transform_openssl::transform(priv, src, size, dst, dsize, flags);
		}

		int default_transform(void *priv, void *src, uint64_t size, void *dst, unsigned int *dsize, unsigned int flags) {
			this->elliptics_transform_openssl::transform(priv, src, size, dst, dsize, flags);
		};

		void cleanup(void *priv) {
			if (override cleanup = this->get_override("cleanup")) {
				cleanup(priv);
				return;
			}

			elliptics_transform_openssl::cleanup(priv);
		}

		void default_cleanup(void *priv) {
			this->elliptics_transform_openssl::cleanup(priv);
		};
};

class elliptics_callback_wrap : public elliptics_callback, public wrapper<elliptics_callback> {
	public:
		elliptics_callback_wrap() {};
		virtual ~elliptics_callback_wrap() {};

		int callback(void) {
			return this->get_override("callback")();
		};
};

class elliptics_node_python : public elliptics_node {
	public:
		elliptics_node_python(unsigned long lptr, elliptics_log &l) :
			elliptics_node((unsigned char *)lptr, &l) {};

		void read_file_by_id(unsigned long lid, const char *file, uint64_t offset, uint64_t size) {
			elliptics_node::read_file((unsigned char *)lid, const_cast<char *>(file), offset, size);
		}

		void read_file_by_data_transform(unsigned long lrem, unsigned int rem_size, const char *file, uint64_t offset, uint64_t size) {
			elliptics_node::read_file((unsigned char *)lrem, rem_size, const_cast<char *>(file), offset, size);
		}

		void write_file_by_id(unsigned long lid, const char *file, uint64_t local_offset, uint64_t offset, uint64_t size,
				unsigned int aflags = 0, unsigned int ioflags = 0) {
			elliptics_node::write_file((unsigned char *)lid, const_cast<char *>(file), local_offset, offset, size, aflags, ioflags);
		}

		void write_file_by_data_transform(unsigned long lrem, unsigned int rem_size, const char *file, uint64_t local_offset,
				uint64_t offset, uint64_t size, unsigned int aflags = 0, unsigned int ioflags = 0) {
			elliptics_node::write_file((unsigned char *)lrem, rem_size, const_cast<char *>(file), local_offset, offset, size, aflags, ioflags);
		}
};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(add_remote_overloads, add_remote, 2, 3);

#if 0
void (elliptics_node::*read_file_by_id)(unsigned char *, char *, uint64_t, uint64_t) = &elliptics_node::read_file;
void (elliptics_node::*read_file_by_data_transform)(void *, unsigned int, char *, uint64_t, uint64_t) = &elliptics_node::read_file;

void (elliptics_node::*read_data_by_id)(unsigned char *, uint64_t, uint64_t, elliptics_callback &) = &elliptics_node::read_data;
void (elliptics_node::*read_data_by_data_transform)(void *, unsigned int, uint64_t, uint64_t, elliptics_callback &) = &elliptics_node::read_data;

void (elliptics_node::*write_file_by_id)(unsigned char *, char *, uint64_t, uint64_t, uint64_t, unsigned int, unsigned int) =
	&elliptics_node::write_file;
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_id_overloads, write_file, 5, 7);

void (elliptics_node::*write_file_by_data_transform)(void *, unsigned int, char *, uint64_t, uint64_t, uint64_t, unsigned int, unsigned int) =
	&elliptics_node::write_file;
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_data_transform_overloads, write_file, 6, 8);

int (elliptics_node::*write_data_by_id)(unsigned char *, void *, unsigned int, elliptics_callback &, unsigned int, unsigned int) =
	&elliptics_node::write_data;
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_data_by_id_overloads, write_data, 4, 6);

int (elliptics_node::*write_data_by_data_transform)(void *, unsigned int, void *, unsigned int, elliptics_callback &,
		unsigned int, unsigned int) = &elliptics_node::write_data;
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_data_by_data_transform_overloads, write_data, 5, 7);
#else
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_id_overloads, write_file_by_id, 5, 7);
BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(write_file_by_data_transform_overloads, write_file_by_data_transform, 6, 8);
#endif

BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<elliptics_log_wrap, boost::noncopyable>("elliptics_log", init<const uint32_t>())
		.def("log", pure_virtual(&elliptics_log::log))
	;

	class_<elliptics_log_file_wrap, boost::noncopyable, bases<elliptics_log> >("elliptics_log_file", init<const char *, const uint32_t>())
		.def("log", &elliptics_log_file::log, &elliptics_log_file_wrap::default_log)
	;

	class_<elliptics_transform_wrap, boost::noncopyable>("elliptics_transform", init<const char *>())
		.def("transform", pure_virtual(&elliptics_transform::transform))
		.def("cleanup", pure_virtual(&elliptics_transform::cleanup))
	;

	class_<elliptics_transform_openssl_wrap, boost::noncopyable, bases<elliptics_transform> >("elliptics_transform_openssl", init<const char *>())
		.def("transform", &elliptics_transform_openssl::transform, &elliptics_transform_openssl_wrap::default_transform)
		.def("cleanup", &elliptics_transform_openssl::cleanup, &elliptics_transform_openssl_wrap::default_cleanup)
	;

	class_<elliptics_callback_wrap, boost::noncopyable>("elliptics_callback")
		.def("callback", pure_virtual(&elliptics_callback::callback))
	;
	class_<elliptics_node>("elliptics_node", init<unsigned char *, elliptics_log *>())
		.def("add_remote", &elliptics_node::add_remote, add_remote_overloads())
		.def("add_transform", &elliptics_node::add_transform)
#if 0
		.def("read_file", read_file_by_id)
		.def("read_file", read_file_by_data_transform)
		.def("read_data", read_data_by_id)
		.def("read_data", read_data_by_data_transform)
		
		.def("write_file", write_file_by_id, write_file_by_id_overloads())
		.def("write_file", write_file_by_data_transform, write_file_by_data_transform_overloads())
		
		.def("write_data", write_data_by_id, write_data_by_id_overloads())
		.def("write_data", write_data_by_data_transform, write_data_by_data_transform_overloads())
#endif
	;
	class_<elliptics_node_python, bases<elliptics_node> >("elliptics_node_python", init<unsigned long, elliptics_log &>())
		.def("add_remote", &elliptics_node::add_remote, add_remote_overloads())
		.def("add_transform", &elliptics_node::add_transform)
		.def("read_file", &elliptics_node_python::read_file_by_id)
		.def("read_file", &elliptics_node_python::read_file_by_data_transform)
		.def("write_file", &elliptics_node_python::write_file_by_id, write_file_by_id_overloads())
		.def("write_file", &elliptics_node_python::write_file_by_data_transform, write_file_by_data_transform_overloads())
	;
};
#endif
