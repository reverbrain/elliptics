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

namespace ioremap { namespace monitor {

namespace status_strings {
const std::string not_found = "HTTP/1.1 404 Not Found\r\n";
const std::string bad_request = "HTTP/1.1 400 Bad Request\r\n";
const std::string ok = "HTTP/1.1 200 OK\r\n";
}

namespace content_strings {
const std::string not_found = "<html>"
	"<head><title>Not Found</title></head>"
	"<body><h1>404 Not Found</h1></body>"
	"</html>";
const std::string bad_request = "<html>"
	"<head><title>Bad Request</title></head>"
	"<body><h1>400 Bad Request</h1></body>"
	"</html>";
const std::string list = "<html>"
	"<body>"
	"GET <a href='/list'>/list</a> - Retrieves a list of acceptable statistics<br/>"
	"GET <a href='/all'>/all</a> - Retrieves all statistics from all submodules<br/>"
	"GET <a href='/cache'>/cache</a> - Retrieves statistics about cache<br/>"
	"GET <a href='/io_queue'>/io_queue</a> - Retrieves statistics about io queue<br/>"
	"GET <a href='/commands'>/commands</a> - Retrieves statistics about commands<br/>"
	"GET <a href='/io_histograms'>/io_histograms</a> - Retrieves statistics about io histograms<br/>"
	"</body>"
	"</html>";
}

const std::map<std::string, int> handlers = {{"/list", DNET_MONITOR_LIST},
	{"/all", DNET_MONITOR_ALL},
	{"/cache", DNET_MONITOR_CACHE},
	{"/io_queue", DNET_MONITOR_IO_QUEUE},
	{"/commands", DNET_MONITOR_COMMANDS},
	{"/io_histograms", DNET_MONITOR_IO_HISTOGRAMS}};

/*!
 * Generates HTTP response for @req category with @content
 */
std::string make_reply(int req, std::string content = "") {
	std::string ret;
	std::string content_type = "application/json";
	switch (req) {
		case DNET_MONITOR_NOT_FOUND: {
			ret = status_strings::not_found;
			content = content_strings::not_found;
			content_type = "text/html";
		}
		break;
		case DNET_MONITOR_BAD: {
			ret = status_strings::bad_request;
			content = content_strings::bad_request;
			content_type = "text/html";
		}
		break;
		case DNET_MONITOR_LIST: {
			ret = status_strings::ok;
			content = content_strings::list;
			content_type = "text/html";
		}
		default:
			ret = status_strings::ok;
		break;
	}

	ret.append("Content-Type: ");
	ret.append(content_type);
	ret.append("\r\n");
	ret.append("Content-Length: ");
	ret.append(std::to_string((long long unsigned int)content.size()));
	ret.append("\r\n\r\n");
	ret.append(content);

	return ret;
}

/*!
 * Parses simple HTTP request and determines requested category
 * @packet - HTTP request packet
 * @size - size of HTTP request packet
 */
int parse(const char* packet, size_t size) {
	const char* end = packet + size;
	const char *method_end = std::find(packet, end, ' ');
	if (method_end >= end || packet == method_end)
		return DNET_MONITOR_BAD;

	const char *url_begin = method_end + 1;
	const char *url_end = std::find(url_begin, end, ' ');
	if (url_end >= end)
		return DNET_MONITOR_BAD;

	auto it = handlers.find(std::string(url_begin, url_end));
	if (it != handlers.end())
		return it->second;

	return DNET_MONITOR_NOT_FOUND;
}

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_HTTP_MISCS_H */
