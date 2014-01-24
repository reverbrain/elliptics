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

/*!
 * Server class which is responsible for:
 *    listening incoming connection
 *    handling simple GET HTTP request
 *    sends simple HTTP response with json statistics of specified category
 */
class server {
public:

	/*!
	 * Constructor: initializes server for @mon to listen @port
	 */
	server(monitor &mon, unsigned int port);

	/*!
	 * Destructor: stops server and freeing all data
	 */
	~server();

	/*!
	 * Stops listening incoming connection and sending responses
	 */
	void stop();

private:
	/*!
	 * Disabling default copy constructor
	 */
	server(const server&);

	/*!
	 * Starts listening monitor port
	 */
	void listen();

	/*!
	 * Asynchronously accepts incoming connecitons
	 */
	void async_accept();

	/*!
	 * Callback which will be called on new accepted incoming connection
	 */
	void handle_accept(std::shared_ptr<handler> h,
	                   const boost::system::error_code &err);

	/*!
	 * Monitor that creates server
	 */
	monitor							&m_monitor;
	/*!
	 * boost::asio kitchen for asynchronous work with sockets
	 */
	boost::asio::io_service			m_io_service;
	boost::asio::ip::tcp::acceptor	m_acceptor;

	/*!
	 * Thread for executing boost::asio
	 */
	std::thread						m_listen;
};

}} /* namespace ioremap::monitor */

#endif /* __DNET_MONITOR_SERVER_HPP */
