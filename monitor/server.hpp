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

#ifndef __DNET_MONITOR_SERVER_HPP
#define __DNET_MONITOR_SERVER_HPP

#include <thread>

#include <boost/asio.hpp>
#include <boost/array.hpp>

namespace ioremap { namespace monitor {

class monitor;
class handler;

class server {
public:
	server(monitor &mon, unsigned int port);
	~server();

	void stop();

private:
	server(const server&);

	void listen();
	void async_accept();
	void handle_accept(std::shared_ptr<handler> h, const boost::system::error_code &err);

	monitor							&m_monitor;
	boost::asio::io_service			m_io_service;
	boost::asio::ip::tcp::acceptor	m_acceptor;
	std::thread						m_listen;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_SERVER_HPP */
