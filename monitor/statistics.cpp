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

#include "statistics.hpp"
#include "monitor.hpp"
#include "../cache/cache.hpp"

namespace ioremap { namespace monitor {
statistics::statistics(monitor& mon)
: m_monitor(mon) {
	memset(m_cmd_stats.c_array(), 0, sizeof(command_counters) * m_cmd_stats.size());
	gettimeofday(&m_start_time, NULL);
}

std::string statistics::report() {
	std::ostringstream out;
	out << "{";
	cache_stat(out);
	struct timeval end_time;
	gettimeofday(&end_time, NULL);
	long diff = (end_time.tv_sec - m_start_time.tv_sec) * 1000000 + (end_time.tv_usec - m_start_time.tv_usec);
	m_start_time = end_time;
	//stat_report(out);
	//cmd_report(out);
	hist_report(out);
	out << ",\"time\":" << diff;
	out << "}";
	return std::move(out.str());
}

void statistics::cache_stat(std::ostringstream &stream) {
	if (!m_monitor.node()->cache)
		return;

	auto cache = static_cast<ioremap::cache::cache_manager*>(m_monitor.node()->cache);
	auto stat = cache->get_total_cache_stats();
	stream << "\"cache_stat\":{"
	       << "\"size\":" << stat.size_of_objects << ","
	       << "\"removing size\":" << stat.size_of_objects_marked_for_deletion << ","
	       << "\"objects\":" << stat.number_of_objects << ","
	       << "\"removing objects\":" << stat.number_of_objects_marked_for_deletion
	       << "}";
}

void statistics::log() {
	dnet_log(m_monitor.node(), DNET_LOG_ERROR, "%s", report().c_str());
}

void statistics::command_counter(int cmd, const int trans, const int err, const int cache,
                     const uint32_t size, const unsigned long time) {
	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	/*std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
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

	m_cmd_info_current.emplace_back(command_stat_info{cmd, size, time, trans == 0, cache != 0});

	if (m_cmd_info_current.size() >= 50000) {
		std::unique_lock<std::mutex> swap_guard(m_cmd_info_previous_mutex);
		m_cmd_info_previous.clear();
		m_cmd_info_current.swap(m_cmd_info_previous);
	}*/

	struct timeval current;
	gettimeofday(&current, NULL);

	histograms *hist = NULL;

	std::unique_lock<std::mutex> guard(m_histograms_mutex);
	if (m_histograms.empty()) {
		m_histograms.emplace_back(histograms());
		hist = &m_histograms.back();
	} else {
		if (current.tv_sec - m_histograms.back().start.tv_sec < 1) {
			hist = &m_histograms.back();
		} else {
			if (m_histograms.size() == 5) {
				m_histograms_previous.clear();
				m_histograms_previous.swap(m_histograms);
			}
			m_histograms.emplace_back(histograms());
			hist = &m_histograms.back();
		}
	}

	hist->command_counter(cmd, trans, cache, size, time);
	m_last_histograms.command_counter(cmd, trans, cache, size, time);
}

void statistics::io_queue_stat(const uint64_t current_size,
                   const uint64_t min_size, const uint64_t max_size,
                   const uint64_t volume, const uint64_t time) {
	m_io_queue_size = current_size;
	m_io_queue_volume = volume;
	m_io_queue_max = max_size;
	m_io_queue_min = min_size;
	m_io_queue_time = time;
}

int statistics::cmd_index(int cmd, const int err) {
	if (cmd >= __DNET_CMD_MAX || cmd <= 0)
		cmd = DNET_CMD_UNKNOWN;

	cmd = cmd * 2 + (err ? 1 : 0);
	return cmd;
}

void statistics::stat_report(std::ostringstream &stream) {
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

void statistics::print(std::ostringstream &stream, const command_stat_info &info, bool comma) {
	if (comma)
		stream << ",";
	stream << "{\"" << dnet_cmd_string(info.cmd) << "\":{"
	<< "\"internal\":" << (info.internal ? "true" : "false") << ","
	<< "\"cache\":" << (info.cache ? "true" : "false") << ","
	<< "\"size\":" << info.size << ","
	<< "\"time\":" << info.time << "}}";
}

void statistics::cmd_report(std::ostringstream &stream) {
	if(m_cmd_info_previous.empty() && m_cmd_info_current.empty())
		return;

	stream << ",\"history\":[";
	bool first_comma = false;
	{
		std::unique_lock<std::mutex> guard(m_cmd_info_previous_mutex);
		const auto begin = m_cmd_info_previous.begin(), end = m_cmd_info_previous.end();
		for (auto it = begin; it != end; ++it) {
			print(stream, *it, it != begin);
		}
		first_comma = !m_cmd_info_previous.empty();
		m_cmd_info_previous.clear();
	} {
		std::unique_lock<std::mutex> guard(m_cmd_info_mutex);
		const auto begin = m_cmd_info_current.begin(), end = m_cmd_info_current.end();
		for (auto it = begin; it != end; ++it) {
			print(stream, *it, it != begin || first_comma);
		}
		m_cmd_info_current.clear();
	}
	stream << "]";
}

histograms statistics::prepare_fivesec_histogram() {
	histograms ret;
	if (!m_histograms.empty()) {
		ret.start = m_histograms.front().start;
		for (auto it = m_histograms.begin(), itEnd = m_histograms.end(); it != itEnd; ++it) {
			auto begin = it->read_counters.begin(), end = it->read_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.read_counters[i-begin].cache += i->cache;
				ret.read_counters[i-begin].disk += i->disk;
				ret.read_counters[i-begin].cache_internal += i->cache_internal;
				ret.read_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->write_counters.begin();
			end = it->write_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.write_counters[i-begin].cache += i->cache;
				ret.write_counters[i-begin].disk += i->disk;
				ret.write_counters[i-begin].cache_internal += i->cache_internal;
				ret.write_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_update_counters.begin();
			end = it->indx_update_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_update_counters[i-begin].cache += i->cache;
				ret.indx_update_counters[i-begin].disk += i->disk;
				ret.indx_update_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_update_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_internal_counters.begin();
			end = it->indx_internal_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_internal_counters[i-begin].cache += i->cache;
				ret.indx_internal_counters[i-begin].disk += i->disk;
				ret.indx_internal_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_internal_counters[i-begin].disk_internal += i->disk_internal;
			}
		}
	}
	auto left = 5 - m_histograms.size();
	if (!m_histograms_previous.empty() && left > 0) {
		for (auto it = m_histograms_previous.rbegin(),
		     itEnd = m_histograms_previous.rbegin() + left;
		     it != itEnd; ++it) {
			auto begin = it->read_counters.begin(), end = it->read_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.read_counters[i-begin].cache += i->cache;
				ret.read_counters[i-begin].disk += i->disk;
				ret.read_counters[i-begin].cache_internal += i->cache_internal;
				ret.read_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->write_counters.begin();
			end = it->write_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.write_counters[i-begin].cache += i->cache;
				ret.write_counters[i-begin].disk += i->disk;
				ret.write_counters[i-begin].cache_internal += i->cache_internal;
				ret.write_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_update_counters.begin();
			end = it->indx_update_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_update_counters[i-begin].cache += i->cache;
				ret.indx_update_counters[i-begin].disk += i->disk;
				ret.indx_update_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_update_counters[i-begin].disk_internal += i->disk_internal;
			}
			begin = it->indx_internal_counters.begin();
			end = it->indx_internal_counters.end();
			for (auto i = begin; i != end; ++i) {
				ret.indx_internal_counters[i-begin].cache += i->cache;
				ret.indx_internal_counters[i-begin].disk += i->disk;
				ret.indx_internal_counters[i-begin].cache_internal += i->cache_internal;
				ret.indx_internal_counters[i-begin].disk_internal += i->disk_internal;
			}
		}
	}
	return ret;
}

void statistics::print_hist(std::ostringstream &stream, const boost::array<hist_counter, 16> &hist, const char *name) {
	auto cache = false, disk = false, cache_internal = false, disk_internal = false, comma = false;
	for (int i = 0; i < 16; ++i) {
		if(hist[i].cache)
			cache = true;
		if(hist[i].disk)
			disk = true;
		if(hist[i].cache_internal)
			cache_internal = true;
		if(hist[i].disk_internal)
			disk_internal = true;

		if(cache && disk && cache_internal && disk_internal)
			break;
	}

	if (cache || disk || cache_internal || disk_internal)
		stream << ",";

	if (cache) {
		stream << "\n\"" << name << "_cache\":{";
		stream << "\n\"0-500 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[0].cache << ","
		       << "\"5001-100000 usecs\":" << hist[1].cache << ","
		       << "\"100001-1000000 usecs\":" << hist[2].cache << ","
		       << "\">1000001 usecs\":" << hist[3].cache
		       << "},\n\"501-1000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[4].cache << ","
		       << "\"5001-100000 usecs\":" << hist[5].cache << ","
		       << "\"100001-1000000 usecs\":" << hist[6].cache << ","
		       << "\">1000001 usecs\":" << hist[7].cache
		       << "},\n\"1001-10000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[8].cache << ","
		       << "\"5001-100000 usecs\":" << hist[9].cache << ","
		       << "\"100001-1000000 usecs\":" << hist[10].cache << ","
		       << "\">1000001 usecs\":" << hist[11].cache
		       << "},\n\">10001 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[12].cache << ","
		       << "\"5001-100000 usecs\":" << hist[13].cache << ","
		       << "\"100001-1000000 usecs\":" << hist[14].cache << ","
		       << "\">1000001 usecs\":" << hist[15].cache << "}}";
		comma = true;
	}

	if (disk) {
		if(comma)
			stream << ",";
		stream << "\n\"" << name << "_disk\":{"
		       << "\n\"0-500 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[0].disk << ","
		       << "\"5001-100000 usecs\":" << hist[1].disk << ","
		       << "\"100001-1000000 usecs\":" << hist[2].disk << ","
		       << "\">1000001 usecs\":" << hist[3].disk
		       << "},\n\"501-1000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[4].disk << ","
		       << "\"5001-100000 usecs\":" << hist[5].disk << ","
		       << "\"100001-1000000 usecs\":" << hist[6].disk << ","
		       << "\">1000001 usecs\":" << hist[7].disk
		       << "},\n\"1001-10000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[8].disk << ","
		       << "\"5001-100000 usecs\":" << hist[9].disk << ","
		       << "\"100001-1000000 usecs\":" << hist[10].disk << ","
		       << "\">1000001 usecs\":" << hist[11].disk
		       << "},\n\">10001 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[12].disk << ","
		       << "\"5001-100000 usecs\":" << hist[13].disk << ","
		       << "\"100001-1000000 usecs\":" << hist[14].disk << ","
		       << "\">1000001 usecs\":" << hist[15].disk << "}}";
		comma = true;
	}

	if(cache_internal) {
		if (comma)
			stream << ",";
		stream << "\n\"" << name << "_cache_internal\":{"
		       << "\n\"0-500 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[0].cache_internal << ","
		       << "\"5001-100000 usecs\":" << hist[1].cache_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[2].cache_internal << ","
		       << "\">1000001 usecs\":" << hist[3].cache_internal
		       << "},\n\"501-1000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[4].cache_internal << ","
		       << "\"5001-100000 usecs\":" << hist[5].cache_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[6].cache_internal << ","
		       << "\">1000001 usecs\":" << hist[7].cache_internal
		       << "},\n\"1001-10000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[8].cache_internal << ","
		       << "\"5001-100000 usecs\":" << hist[9].cache_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[10].cache_internal << ","
		       << "\">1000001 usecs\":" << hist[11].cache_internal
		       << "},\n\">10001 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[12].cache_internal << ","
		       << "\"5001-100000 usecs\":" << hist[13].cache_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[14].cache_internal << ","
		       << "\">1000001 usecs\":" << hist[15].cache_internal << "}}";
		comma = true;
	}


	if (disk_internal) {
		if (comma)
			stream << ",";
		stream << "\n\"" << name << "_disk_internal\":{"
		       << "\n\"0-500 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[0].disk_internal << ","
		       << "\"5001-100000 usecs\":" << hist[1].disk_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[2].disk_internal << ","
		       << "\">1000001 usecs\":" << hist[3].disk_internal
		       << "},\n\"501-1000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[4].disk_internal << ","
		       << "\"5001-100000 usecs\":" << hist[5].disk_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[6].disk_internal << ","
		       << "\">1000001 usecs\":" << hist[7].disk_internal
		       << "},\n\"1001-10000 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[8].disk_internal << ","
		       << "\"5001-100000 usecs\":" << hist[9].disk_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[10].disk_internal << ","
		       << "\">1000001 usecs\":" << hist[11].disk_internal
		       << "},\n\">10001 bytes\":{"
		       << "\"0-5000 usecs\":" << hist[12].disk_internal << ","
		       << "\"5001-100000 usecs\":" << hist[13].disk_internal << ","
		       << "\"100001-1000000 usecs\":" << hist[14].disk_internal << ","
		       << "\">1000001 usecs\":" << hist[15].disk_internal
		       << "}}";
	}
}

void statistics::hist_report(std::ostringstream &stream) {
	std::unique_lock<std::mutex> guard(m_histograms_mutex);
	auto fivesec_hist = prepare_fivesec_histogram();
	print_hist(stream, m_last_histograms.read_counters, "last_reads");
	print_hist(stream, m_last_histograms.write_counters, "last_writes");
	print_hist(stream, m_last_histograms.indx_update_counters, "last_indx_updates");
	print_hist(stream, m_last_histograms.indx_internal_counters, "last_indx_internals");
	print_hist(stream, fivesec_hist.read_counters, "5sec_reads");
	print_hist(stream, fivesec_hist.write_counters, "5sec_writes");
	print_hist(stream, fivesec_hist.indx_update_counters, "5sec_indx_updates");
	print_hist(stream, fivesec_hist.indx_internal_counters, "5sec_indx_internals");

	m_last_histograms.clear();
}

}} /* namespace ioremap::monitor */
