/*
 * 2015+ Copyright (c) Budnik Andrey <budnik27@gmail.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <memory>
#include <cstdio>
#include "test_base.hpp"
#include "../library/crypto/sha512.h"

#include <boost/bind/bind.hpp>
using namespace boost::placeholders;

#define BOOST_TEST_NO_MAIN
#include <boost/test/included/unit_test.hpp>

#include <boost/program_options.hpp>

using namespace ioremap::elliptics;
using namespace boost::unit_test;

namespace tests {

/*
 * Create temporary file and fill it with file_size random bytes.
 */
static int create_file(const size_t file_size)
{
	FILE *tmp = tmpfile();
	if (tmp == nullptr)
		return -errno;

	std::unique_ptr<char[]> buf(new char[file_size]);
	fwrite(buf.get(), sizeof(char), file_size, tmp);
	return fileno(tmp);
}

/*
 * Calls multiple times sha512_file(), sha512_file_ctx(), sha512_buffer() with
 * random offset & count parameters. Checks that all hash functions return identical
 * hash values.
 */
static void test_sha512_file_cross_memory()
{
	const size_t file_size = 2 * 32768; // 2 * BLOCKSIZE
	int fd = create_file(file_size);
	BOOST_CHECK_MESSAGE(fd >= 0, "could not create temporary file");

	const size_t num_iter = 1000;
	char hash_file[64], hash_file_ctx[64], hash_memory[64];
	struct sha512_ctx ctx;
	std::unique_ptr<char[]> buffer(new char[file_size]);
	int err;

	for (size_t i = 0; i < num_iter; ++i) {
		const off_t offset = rand() % file_size;
		const size_t count = rand() % file_size;

		sha512_init_ctx(&ctx);
		err = sha512_file_ctx(fd, offset, count, &ctx);
		if (offset + count > file_size) {
			BOOST_CHECK_MESSAGE(err == -ESPIPE,
				"sha512_file_ctx() must return ESPIPE when offset + count > file_size");
		} else {
			BOOST_CHECK_MESSAGE(err == 0,
				"Unexpected error during sha512_file_ctx() call");
		}
		sha512_finish_ctx(&ctx, hash_file_ctx);

		err = sha512_file(fd, offset, count, hash_file);
		if (offset + count > file_size) {
			BOOST_CHECK_MESSAGE(err == -ESPIPE,
				"sha512_file() must return ESPIPE when offset + count > file_size");
			continue;
		} else {
			BOOST_CHECK_MESSAGE(err == 0,
				"Unexpected error during sha512_file() call");
		}

		err = pread(fd, buffer.get(), count, offset);
		BOOST_CHECK_MESSAGE(err == static_cast<int>(count), "pread() failed, could not read test file");
		sha512_buffer(buffer.get(), count, hash_memory);

		BOOST_CHECK_MESSAGE(memcmp(hash_file, hash_memory, sizeof(hash_file)) == 0,
			"hash_file != hash_memory: sha512_file() or sha512_buffer() function is broken");
		BOOST_CHECK_MESSAGE(memcmp(hash_file_ctx, hash_memory, sizeof(hash_file)) == 0,
			"hash_file_ctx != hash_memory: sha512_file_ctx() function is broken");
	}
}

bool register_tests(test_suite *suite)
{
	ELLIPTICS_TEST_CASE_NOARGS(test_sha512_file_cross_memory);

	return true;
}

boost::unit_test::test_suite *register_tests(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::variables_map vm;
	bpo::options_description generic("Test options");

	std::string path;

	generic.add_options()
			("help", "This help message")
			("path", bpo::value(&path), "Path where to store everything")
			;

	bpo::store(bpo::parse_command_line(argc, argv, generic), vm);
	bpo::notify(vm);

	if (vm.count("help")) {
		std::cerr << generic;
		return nullptr;
	}

	test_suite *suite = new ELLIPTICS_MAKE_TEST_SUITE("crypto library test suite");
	register_tests(suite);

	return suite;
}

} // namespace test

int main(int argc, char *argv[])
{
	srand(time(nullptr));
	return unit_test_main(tests::register_tests, argc, argv);
}
