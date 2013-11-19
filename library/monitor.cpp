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
		//async_read();
		async_write();
	}

	boost::asio::ip::tcp::socket &socket() {
		return m_socket;
	}

private:
	/*void async_read() {
		auto self(shared_from_this());
		m_socket.async_read_some(boost::asio::buffer(m_buffer),
		                         std::bind(&handler::handle_read, self,
		                                   std::placeholders::_1,
		                                   std::placeholders::_2));
	}*/

	void async_write(std::string data) {
		auto self(shared_from_this());
		m_report = std::move(data);
		boost::asio::async_write(m_socket, boost::asio::buffer(m_report),
		                         std::bind(&handler::handle_write, self,
		                                   std::placeholders::_1,
		                                   std::placeholders::_2));
	}

	//void handle_read(const boost::system::error_code &err, size_t bytes_transferred);

	void async_write();

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

struct command_counters {
	uint_fast64_t	cache_successes;
	uint_fast64_t	cache_failures;
	uint_fast64_t	cache_internal_successes;
	uint_fast64_t	cache_internal_failures;
	uint_fast64_t	disk_successes;
	uint_fast64_t	disk_failures;
	uint_fast64_t	disk_internal_successes;
	uint_fast64_t	disk_internal_failures;

	uint_fast64_t	cache_size;
	uint_fast64_t	cache_internal_size;
	uint_fast64_t	disk_size;
	uint_fast64_t	disk_internal_size;
	uint_fast64_t	cache_time;
	uint_fast64_t	disk_time;
	uint_fast64_t	cache_internal_time;
	uint_fast64_t	disk_internal_time;
};

struct command_stat_info {
	int				cmd;
	size_t			size;
	unsigned long	time;
	bool			internal;
};

class monitor {
public:
	monitor(struct dnet_node *n, struct dnet_config *cfg)
	: m_node(n)
	, m_acceptor(m_io_service, boost::asio::ip::tcp::tcp::endpoint(boost::asio::ip::tcp::v4(), cfg->monitor_port))
	{
		m_listen = std::thread(std::bind(&monitor::listen, this));
		memset(m_cmd_stats.c_array(), 0, sizeof(command_counters) * m_cmd_stats.size());
		gettimeofday(&m_start_time, NULL);
	}

	~monitor() {
		stop();
		m_listen.join();
	}

	void stop() {
		m_io_service.stop();
	}

	std::string report() {
		std::ostringstream out;
		out << "{\"cache_memory\":" << m_cache_memory;
		struct timeval end_time;
		gettimeofday(&end_time, NULL);
		long diff = (end_time.tv_sec - m_start_time.tv_sec) * 1000000 + (end_time.tv_usec - m_start_time.tv_usec);
		m_start_time = end_time;
		stat_report(out);
		cmd_report(out);
		out << ",\"time\":" << diff;
		out << "}";
		return std::move(out.str());
	}

	void log() {
		dnet_log(m_node, DNET_LOG_ERROR, "%s", report().c_str());
	}

	void increase_cache(const size_t &size) {
		m_cache_memory += size;
	}

	void decrease_cache(const size_t &size) {
		m_cache_memory -= size;
	}

	void command_counter(int cmd, const int trans, const int err, const int cache,
	                     const uint32_t size, const unsigned long time) {
		if (cmd >= __DNET_CMD_MAX || cmd <= 0)
			cmd = DNET_CMD_UNKNOWN;

		std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
		if (cache) {
			if (trans) {
				if(!err)
					m_cmd_stats[cmd].cache_successes++;
				else
					m_cmd_stats[cmd].cache_failures++;
				m_cmd_stats[cmd].cache_size += size;
				m_cmd_stats[cmd].cache_time += time;
			} else {
				if(!err)
					m_cmd_stats[cmd].cache_internal_successes++;
				else
					m_cmd_stats[cmd].cache_internal_failures++;
				m_cmd_stats[cmd].cache_internal_size += size;
				m_cmd_stats[cmd].cache_internal_time += time;
			}
		} else {
			if (trans) {
				if(!err)
					m_cmd_stats[cmd].disk_successes++;
				else
					m_cmd_stats[cmd].disk_failures++;
				m_cmd_stats[cmd].disk_size += size;
				m_cmd_stats[cmd].disk_time += time;
			} else {
				if(!err)
					m_cmd_stats[cmd].disk_internal_successes++;
				else
					m_cmd_stats[cmd].disk_internal_failures++;
				m_cmd_stats[cmd].disk_internal_size += size;
				m_cmd_stats[cmd].disk_internal_time += time;
			}
		}

		m_cmd_info_current.emplace_back(command_stat_info{cmd, size, time, trans == 0});

		if (m_cmd_info_current.size() >= 1000) {
			std::unique_lock<std::mutex> swap_guard(m_cmd_info_previous_mutex);
			m_cmd_info_previous.clear();
			m_cmd_info_current.swap(m_cmd_info_previous);
		}
	}

	void io_queue_stat(const uint64_t current_size,
	                   const uint64_t min_size, const uint64_t max_size,
	                   const uint64_t volume, const uint64_t time) {
		m_io_queue_size = current_size;
		m_io_queue_volume = volume;
		m_io_queue_max = max_size;
		m_io_queue_min = min_size;
		m_io_queue_time = time;
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

	void stat_report(std::ostringstream &stream) {
		stream << ",\"command_stat\":{";
		std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
		for (int i = 1; i < __DNET_CMD_MAX; ++i) {
			stream << "\"" << dnet_cmd_string(i) << "\":{"
			<< "\"cache\":{\"successes\":" << m_cmd_stats[i].cache_successes
			<< ",\"failures\":" << m_cmd_stats[i].cache_failures << "},"
			<< "\"cache_internal\":{\"successes\":" << m_cmd_stats[i].cache_internal_successes
			<< ",\"failures\": " << m_cmd_stats[i].cache_internal_failures << "},"
			<< "\"disk\":{\"successes\":" << m_cmd_stats[i].disk_successes
			<< ",\"failures\":" << m_cmd_stats[i].disk_failures << "},"
			<< "\"disk_internal\":{\"successes\":" << m_cmd_stats[i].disk_internal_successes
			<< ",\"failures\":" << m_cmd_stats[i].disk_internal_failures << "},"
			<< "\"cache_size\":" << m_cmd_stats[i].cache_size << ","
			<< "\"cache_intenal_size\":" << m_cmd_stats[i].cache_internal_size << ","
			<< "\"disk_size\": " << m_cmd_stats[i].disk_size << ","
			<< "\"disk_internal_size\":" << m_cmd_stats[i].disk_internal_size << ","
			<< "\"cache_time\":" << m_cmd_stats[i].cache_time << ","
			<< "\"cache_internal_time\":" << m_cmd_stats[i].cache_internal_time << ","
			<< "\"disk_time\":" << m_cmd_stats[i].disk_time << ","
			<< "\"disk_internal_time\":" << m_cmd_stats[i].disk_internal_time << "}";
			if (i < __DNET_CMD_MAX - 1)
				stream << ",";
		}
		stream << "}";
		memset(m_cmd_stats.c_array(), 0, sizeof(command_counters) * m_cmd_stats.size());
	}

	void cmd_report(std::ostringstream &stream) {
		if(m_cmd_info_previous.empty() && m_cmd_info_current.empty())
			return;

		stream << ",\"command_stat\":{";
		{
			std::unique_lock<std::mutex> guard(m_cmd_info_previous_mutex);
			const auto begin = m_cmd_info_previous.begin(), end = m_cmd_info_previous.end();
			for (auto it = begin; it != end; ++it) {
				if (it != begin)
					stream << ",";
				stream << "\"" << dnet_cmd_string(it->cmd) << "\":{"
				<< "\"internal\":" << (it->internal ? "true" : "false") << ","
				<< "\"size\":" << it->size << ","
				<< "\"time\":" << it->time << "},";
			}
			m_cmd_info_previous.clear();
		} {
			std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
			const auto begin = m_cmd_info_current.begin(), end = m_cmd_info_current.end();
			for (auto it = begin; it != end; ++it) {
				if (it != begin)
					stream << ",";
				stream << "\"" << dnet_cmd_string(it->cmd) << "\": {"
				<< "\"internal\":" << (it->internal ? "true" : "false") << ","
				<< "\"size\":" << it->size << ","
				<< "\"time\":" << it->time << "}";
			}
			m_cmd_info_current.clear();
		}
		stream << "}";
	}


	std::atomic_uint_fast64_t	m_cache_memory;
	std::atomic_uint_fast64_t	m_io_queue_size;
	std::atomic_uint_fast64_t	m_io_queue_volume;
	std::atomic_uint_fast64_t	m_io_queue_max;
	std::atomic_uint_fast64_t	m_io_queue_min;
	std::atomic_uint_fast64_t	m_io_queue_time;

	mutable std::mutex				m_cmd_info_mutex;
	boost::array<command_counters, __DNET_CMD_MAX> m_cmd_stats;

	dnet_node						*m_node;
	std::thread						m_listen;
	boost::asio::io_service			m_io_service;
	boost::asio::ip::tcp::acceptor	m_acceptor;

	struct timeval					m_start_time;

	std::vector<command_stat_info>	m_cmd_info_current;
	mutable std::mutex				m_cmd_info_previous_mutex;
	std::vector<command_stat_info>	m_cmd_info_previous;
};

void handler::async_write() {
	async_write(std::move(m_monitor.report()));
}

/*void handler::handle_read(const boost::system::error_code &err, size_t bytes_transferred) {
	if (err || bytes_transferred < 1) {
		close();
		return;
	}

	async_write(std::move(m_monitor.report()));
}*/

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

void dnet_monitor_log(void *monitor) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->log();
}

void monitor_increase_cache(void *monitor, const size_t size) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->increase_cache(size);
}

void monitor_decrease_cache(void *monitor, const size_t size) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->decrease_cache(size);
}

void monitor_command_counter(void *monitor, const int cmd, const int trans,
                             const int err, const int cache,
                             const uint32_t size, const unsigned long time) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->command_counter(cmd, trans, err, cache, size, time);
}

void monitor_io_queue_stat(void *monitor, const uint64_t current_size,
                           const uint64_t min_size, const uint64_t max_size,
                           const uint64_t volume, const uint64_t time) {
	if (monitor)
		static_cast<ioremap::monitor::monitor*>(monitor)->io_queue_stat(current_size, min_size, max_size, volume, time);
}