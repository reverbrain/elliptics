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

#include "server.hpp"
#include "monitor.hpp"

#include "../library/elliptics.h"
#include "http_miscs.hpp"

namespace ioremap { namespace monitor {

class handler: public std::enable_shared_from_this<handler> {
public:
	handler(monitor &mon, boost::asio::io_service &io_service)
	: m_monitor(mon)
	, m_socket(io_service)
	, m_remote("")
	{}

	void start() {
		m_remote = m_socket.remote_endpoint().address().to_string();
		dnet_log(m_monitor.node(), DNET_LOG_INFO, "monitor: server: accepted client: %s:%d", m_remote.c_str(), m_socket.remote_endpoint().port());
		async_read();
	}

	boost::asio::ip::tcp::socket &socket() {
		return m_socket;
	}

private:
	void async_read();
	void async_write(std::string data);
	void handle_read(const boost::system::error_code &err, size_t size);
	void handle_write();
	void close();

	uint64_t parse_request(size_t size);

	monitor							&m_monitor;
	boost::asio::ip::tcp::socket	m_socket;
	std::string						m_remote;
	boost::array<char, 1024>		m_buffer;
	std::string						m_report;
};

static boost::asio::ip::tcp convert_family(int family) {
	return family == AF_INET6 ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4();
}

server::server(monitor &mon, unsigned int port, int family)
: m_monitor(mon)
, m_acceptor(m_io_service, boost::asio::ip::tcp::endpoint(convert_family(family), port)) {
	m_listen = std::thread(std::bind(&server::listen, this));
}

server::~server() {
	stop();
	m_listen.join();
}

void server::listen() {
	while (!m_monitor.node()->need_exit) {
		try {
			async_accept();
			m_io_service.run();
		} catch (const std::exception &e) {
			dnet_log(m_monitor.node(), DNET_LOG_ERROR, "monitor: server: got exception: %s, restarting it", e.what());
		} catch (...) {
			dnet_log(m_monitor.node(), DNET_LOG_ERROR, "monitor: server: got unknown exception, restarting");
		}
	}
}

void server::async_accept() {
	auto h = std::make_shared<handler>(m_monitor, m_io_service);
	m_acceptor.async_accept(h->socket(),
	                        std::bind(&server::handle_accept, this,
	                                  h,
	                                  std::placeholders::_1));
}

void server::handle_accept(std::shared_ptr<handler> h, const boost::system::error_code &err) {
	if (!err) {
		h->start();
	}

	async_accept();
}


void server::stop() {
	m_io_service.stop();
}

void handler::async_read() {
	auto self(shared_from_this());
	m_socket.async_read_some(boost::asio::buffer(m_buffer),
	                         std::bind(&handler::handle_read, self,
	                                   std::placeholders::_1,
	                                   std::placeholders::_2));
}

void handler::handle_read(const boost::system::error_code &err, size_t size) {
	if (err) {
		close();
		return;
	}

	auto req = parse_request(size);
	std::string content = "";

	if (req > 0) {
		dnet_log(m_monitor.node(), DNET_LOG_DEBUG, "monitor: server: got statistics request for categories: %lx from: %s:%d", req, m_remote.c_str(), m_socket.remote_endpoint().port());
		content = m_monitor.get_statistics().report(req);
	}

	std::string reply = make_reply(req, content);
	async_write(reply);
}

void handler::async_write(std::string data) {
	auto self(shared_from_this());
	m_report = std::move(data);
	dnet_log(m_monitor.node(), DNET_LOG_DEBUG, "monitor: server: send requested statistics: started: %s:%d, size: %lu", m_remote.c_str(), m_socket.remote_endpoint().port(), m_report.size());
	boost::asio::async_write(m_socket, boost::asio::buffer(m_report),
	                         std::bind(&handler::handle_write, self));
}

void handler::handle_write() {
	dnet_log(m_monitor.node(), DNET_LOG_DEBUG, "monitor: server: send requested statistics: finished: %s:%d", m_remote.c_str(), m_socket.remote_endpoint().port());
	close();
}

void handler::close() {
	boost::system::error_code ec;
	m_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
}

uint64_t handler::parse_request(size_t size) {
	return parse(m_buffer.data(), size);
}

}} /* namespace ioremap::monitor */
