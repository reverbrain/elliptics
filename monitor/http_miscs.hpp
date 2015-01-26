/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
 *
 * This file is part of Elliptics.
 *
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_MONITOR_HTTP_MISCS_H
#define __DNET_MONITOR_HTTP_MISCS_H

#include <string>

#include <boost/lexical_cast.hpp>

namespace ioremap { namespace monitor {

namespace status_strings {
const std::string not_found = "HTTP/1.1 404 Not Found\r\n";
const std::string bad_request = "HTTP/1.1 400 Bad Request\r\n";
const std::string ok = "HTTP/1.1 200 OK\r\n";
}

namespace content_strings {
const std::string not_found = "<html>\n"
	"<head><title>Not Found</title></head>\n"
	"<body><h1>404 Not Found</h1></body>\n"
	"</html>\n";
const std::string bad_request = "<html>\n"
	"<head><title>Bad Request</title></head>\n"
	"<body><h1>400 Bad Request</h1></body>\n"
	"</html>\n";
const std::string list = "<html>\n"
	"<body>\n"
	"GET <a href='/list'>/list</a> - Retrieves a list of acceptable statistics<br/>\n"
	"GET <a href='/all'>/all</a> - Retrieves all statistics from all submodules<br/>\n"
	"GET <a href='/cache'>/cache</a> - Retrieves statistics about cache<br/>\n"
	"GET <a href='/io'>/io</a> - Retrieves statistics about io statistics<br/>\n"
	"GET <a href='/commands'>/commands</a> - Retrieves statistics about commands<br/>\n"
	"GET <a href='/io_histograms'>/io_histograms</a> - Retrieves statistics about io histograms<br/>\n"
	"GET <a href='/backend'>/backend</a> - Retrieves statistics about backend<br/>\n"
	"GET <a href='/stats'>/stats</a> - Retrieves in-process runtime statistics<br/>\n"
	"GET <a href='/procfs'>/procfs</a> - Retrieves system statistics about process<br/>\n"
	"GET <a href='/top'>/top</a> - Retrieves top keys arranged by traffic size and access frequency<br/>\n"
	"</body>\n"
	"</html>\n";
}

const std::string categories_url = "/?categories=";

const std::map<std::string, uint64_t> handlers = {
	{"/all", DNET_MONITOR_ALL},
	{"/cache", DNET_MONITOR_CACHE},
	{"/io", DNET_MONITOR_IO},
	{"/commands", DNET_MONITOR_COMMANDS},
	{"/backend", DNET_MONITOR_BACKEND},
	{"/stats", DNET_MONITOR_STATS},
	{"/procfs", DNET_MONITOR_PROCFS},
	{"/top", DNET_MONITOR_TOP}
};

/*!
 * Generates HTTP response for @req category with @content
 */
std::string make_reply(uint64_t req, std::string content = "") {
	std::stringstream ret;
	std::string content_type = "application/json";
	if (req == 0) {
		ret << status_strings::ok;
		content = content_strings::list;
		content_type = "text/html";
	} else {
		ret << status_strings::ok;
	}

	ret << "Content-Type: " << content_type << "\r\n"
		<< "Content-Length: " << std::to_string((long long unsigned int)content.size()) << "\r\n"
		<< (req != 0 ? "Content-Encoding: deflate\r\n" : "")
		<< "Connection: close\r\n"
		<< "\r\n"
		<< content;

	return ret.str();
}

/*!
 * Parses simple HTTP request and determines requested category
 * @packet - HTTP request packet
 * @size - size of HTTP request packet
 */
uint64_t parse(const char* packet, size_t size) {
	const char* end = packet + size;
	const char *method_end = std::find(packet, end, ' ');
	if (method_end >= end || packet == method_end)
		return 0;

	const char *url_begin = method_end + 1;
	const char *url_end = std::find(url_begin, end, ' ');
	if (url_end >= end)
		return 0;

	auto it = handlers.find(std::string(url_begin, url_end));
	if (it != handlers.end())
		return it->second;
	else if (ssize_t(categories_url.size()) < (url_end - url_begin) &&
	         strncmp(url_begin, categories_url.c_str(), categories_url.size()) == 0) {
		const char *categories = url_begin + categories_url.size();
		try {
			return boost::lexical_cast<uint64_t>(std::string(categories, url_end));
		} catch(...) {
			printf("Couldn't parse categories: %s\n", categories);
		}
	}

	return 0;
}

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_HTTP_MISCS_H */
