/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * 2012+ Copyright (c) Ruslan Nigmatullin <euroelessar@yandex.ru>
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

#ifndef __DNET_MONITOR_COMPRESS_HPP
#define __DNET_MONITOR_COMPRESS_HPP

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/detail/config/zlib.hpp>

namespace ioremap { namespace monitor {

static inline std::string compress(const std::string &data) {
	std::string compressed;

	boost::iostreams::filtering_streambuf<boost::iostreams::output> out;
	out.push(boost::iostreams::zlib_compressor());
	out.push(std::back_inserter(compressed));
	boost::iostreams::copy(boost::make_iterator_range(data), out);
	return compressed;
}

static inline std::string decompress(const std::string &data) {
	std::string decompressed;

	boost::iostreams::filtering_streambuf<boost::iostreams::input> in;
	in.push(boost::iostreams::zlib_decompressor());
	in.push(boost::make_iterator_range(data));
	boost::iostreams::copy(in, std::back_inserter(decompressed));
	return decompressed;
}

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_COMPRESS_HPP */
