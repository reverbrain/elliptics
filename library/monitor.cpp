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

#include "monitor.h"

#include <exception>
#include <atomic>
#include <sstream>
#include <functional>
#include <thread>

#include <boost/asio.hpp>
#include <boost/array.hpp>

#include "elliptics.h"

namespace ioremap { namespace monitor {

class monitor;

class handler : public std::enable_shared_from_this<handler> {
public:
	handler(monitor &mon, boost::asio::io_service &io_service)
	: m_monitor(mon)
	, m_socket(io_service)
	{}

	void start() {
		async_read();
	}

	boost::asio::ip::tcp::socket &socket() {
		return m_socket;
	}

private:
	void async_read() {
		auto self(shared_from_this());
		m_socket.async_read_some(boost::asio::buffer(m_buffer),
		                         std::bind(&handler::handle_read, self,
		                                   std::placeholders::_1,
		                                   std::placeholders::_2));
	}

	void async_write(std::string data) {
		auto self(shared_from_this());
		m_report = std::move(data);
		boost::asio::async_write(m_socket, boost::asio::buffer(m_report),
		                         std::bind(&handler::handle_write, self,
		                                   std::placeholders::_1,
		                                   std::placeholders::_2));
	}

	void handle_read(const boost::system::error_code &err, size_t bytes_transferred);

	void handle_write(const boost::system::error_code &, size_t) {
		close();
	}

	void close() {
		boost::system::error_code ec;
		m_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
	}

	monitor							&m_monitor;
	boost::asio::ip::tcp::socket	m_socket;
	boost::array<char, 64>			m_buffer;
	std::string						m_report;
};

class monitor {
public:
	monitor(struct dnet_node *n, struct dnet_config *cfg)
	: m_node(n)
	, m_acceptor(m_io_service, boost::asio::ip::tcp::tcp::endpoint(boost::asio::ip::tcp::v4(), cfg->monitor_port))
	{
		m_listen = std::thread(std::bind(&monitor::listen, this));
	}

	~monitor() {
		stop();
		m_listen.join();
	}

	void stop() {
		m_io_service.stop();
	}

	std::string report() const {
		std::ostringstream out;
		out << "{\n\t\"cache_memory\": " << m_cache_memory;
		stat_report(m_cache_stat, "cache_stat", out);
		stat_report(m_disk_stat, "disk_stat", out);
		out << "\n}\n";
		return std::move(out.str());
	}

	void log() const {
		dnet_log(m_node, DNET_LOG_ERROR, "%s", report().c_str());
	}

	void increase_cache(const size_t &size) {
		m_cache_memory += size;
	}

	void decrease_cache(const size_t &size) {
		m_cache_memory -= size;
	}

	void cache_stat(int cmd, const int err) {
		m_cache_stat[cmd_index(cmd, err)]++;
	}

	void disk_stat(int cmd, const int err) {
		m_disk_stat[cmd_index(cmd, err)]++;
	}

private:

	int cmd_index(int cmd, const int err) {
		if (cmd >= __DNET_CMD_MAX || cmd <= 0)
			cmd = DNET_CMD_UNKNOWN;

		cmd = cmd * 2 + (err ? 1 : 0);
		return cmd;
	}

	void listen() {
		try {
			async_accept();
			m_io_service.run();
		} catch (const std::exception &e) {
			dnet_log(m_node, DNET_LOG_ERROR,
			         "Could not run monitor io_service: %s\n", e.what());
		}
	}

	void async_accept() {
		auto h = std::make_shared<handler>(*this, m_io_service);
		m_acceptor.async_accept(h->socket(),
		                        std::bind(&monitor::handle_accept, this,
		                                  h,
		                                  std::placeholders::_1));
	}

	void handle_accept(std::shared_ptr<handler> h, const boost::system::error_code &err) {
		if (!err) {
			h->start();
		}

		async_accept();
	}

	static void stat_report(const std::atomic_uint_fast32_t *stat, const char *stat_name, std::ostringstream &stream) {
		stream << ",\n\t\"" << stat_name << "\": {";
		for (int i = 1; i < __DNET_CMD_MAX; ++i) {
			stream << "\n\t\t\"" << dnet_cmd_string(i)
			<< "\": {\"successes\": " << stat[2 * i]
			<< ", \"failures\": " << stat[2 * i + 1]
			<< "}";
			if (i < __DNET_CMD_MAX - 1)
				stream << ",";
		}
		stream << "\n\t}";
	}

	std::atomic_uint_fast32_t	m_cache_memory;
	std::atomic_uint_fast32_t	m_cache_stat[__DNET_CMD_MAX * 2];
	std::atomic_uint_fast32_t	m_disk_stat[__DNET_CMD_MAX * 2];

	dnet_node						*m_node;
	std::thread						m_listen;
	boost::asio::io_service			m_io_service;
	boost::asio::ip::tcp::acceptor	m_acceptor;
};

void handler::handle_read(const boost::system::error_code &err, size_t bytes_transferred) {
	if (err || bytes_transferred < 1) {
		close();
		return;
	}

	async_write(std::move(m_monitor.report()));
}

}} /* namespace ioremap::monitor */

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg) {
	if (!cfg->monitor_port) {
		n->monitor = NULL;
		dnet_log(n, DNET_LOG_INFO, "Monitor hasn't been initialized because monitor port is zero\n");
		return 0;
	}

	try {
		n->monitor = static_cast<void*>(new ioremap::monitor::monitor(n, cfg));
	} catch (const std::exception &e) {
		dnet_log(n, DNET_LOG_ERROR, "Could not create monitor: %s\n", e.what());
		return -ENOMEM;
	}

	return 0;
}

void dnet_monitor_exit(struct dnet_node *n) {
	if (n->monitor)
		delete (ioremap::monitor::monitor*)n->monitor;
}

void dnet_monitor_log(const void *monitor) {
	if (monitor)
		static_cast<const ioremap::monitor::monitor*>(monitor)->log();
}

void monitor_increase_cache(void *monitor, const size_t size) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->increase_cache(size);
}

void monitor_decrease_cache(void *monitor, const size_t size) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->decrease_cache(size);
}

void monitor_cache_stat(void *monitor, const int cmd, const int err) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->cache_stat(cmd, err);
}

void monitor_disk_stat(void *monitor, const int cmd, const int err) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->disk_stat(cmd, err);
}
