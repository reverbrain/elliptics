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
	;
};

#else
#include "elliptics/cppdef.h"

using namespace boost::python;

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


BOOST_PYTHON_MODULE(libelliptics_python) {
	class_<elliptics_log_wrap, boost::noncopyable>("elliptics_log", init<const uint32_t>())
		.def("log", pure_virtual(&elliptics_log::log))
	;

	class_<elliptics_log_file_wrap, boost::noncopyable, bases<elliptics_log> >("elliptics_log_file", init<const char *, const uint32_t>())
		.def("log", &elliptics_log_file::log, &elliptics_log_file_wrap::default_log)
	;
};
#endif
