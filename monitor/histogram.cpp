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

#include "histogram.hpp"

#include <sys/time.h>
#include <algorithm>

namespace ioremap { namespace monitor {

bool cmp(const std::pair<uint64_t, std::string> &lh,
         const std::pair<uint64_t, std::string> &rh) {
	return (lh.first < rh.first);
}

histogram::data::data(size_t size, const struct timeval *time)
: counters(size, 0) {
	if (time == NULL)
		gettimeofday(&timestamp, NULL);
	else
		timestamp = *time;
}

histogram::histogram(const std::vector<std::pair<uint64_t, std::string>> &xs,
                     const std::vector<std::pair<uint64_t, std::string>> &ys,
                     size_t history_depth)
: m_xs(xs)
, m_ys(ys)
, m_last_data(xs.size() * ys.size())
, m_history_depth(history_depth) {
	std::sort(m_xs.begin(), m_xs.end(), cmp);
	std::sort(m_ys.begin(), m_ys.end(), cmp);
	m_snapshots.emplace_back(xs.size() * ys.size());
}

void histogram::update(uint64_t x, uint64_t y) {
	validate_snapshots();

	auto indx = get_indx(x, y);
	m_snapshots.rbegin()->counters[indx] += 1;
	m_last_data.counters[indx] += 1;
}

struct lower_cmp {
	bool operator() (const std::pair<uint64_t, std::string> &lh,
	                 uint64_t rh) {
		return (lh.first < rh);
	}
};

size_t histogram::get_indx(uint64_t x, uint64_t y) {
	auto indx_x = std::lower_bound(m_xs.begin(), m_xs.end(), x, lower_cmp());
	auto indx_y = std::lower_bound(m_ys.begin(), m_ys.end(), y, lower_cmp());

	auto x_coord = std::distance(m_xs.begin(), indx_x);
	auto y_coord = std::distance(m_ys.begin(), indx_y);
	auto line_size = m_xs.size() - 1;

	return x_coord * line_size + y_coord;
}

rapidjson::Value& histogram::print_data(rapidjson::Value &stat_value,
                                        rapidjson::Document::AllocatorType &allocator,
                                        histogram::data &data) {
	rapidjson::Value data_value(rapidjson::kObjectType);
	for (size_t i = 0, size = data.counters.size(); i < size; ++i) {
		auto x = i % m_xs.size();
		auto y = i / m_xs.size();
		if (x == 0 && i != 0) {
			stat_value.AddMember(m_ys[y - 1].second.c_str(), data_value, allocator);
			data_value.SetObject();
		}
		data_value.AddMember(m_xs[x].second.c_str(), data.counters[i], allocator);
	}

	stat_value.AddMember(m_ys.rbegin()->second.c_str(), data_value, allocator);

	stat_value.AddMember("time",
	                     rapidjson::Value(rapidjson::kObjectType)
	                         .AddMember("tv_sec", data.timestamp.tv_sec, allocator)
	                         .AddMember("tv_usec", data.timestamp.tv_usec, allocator),
	                     allocator);

	return stat_value;
}

rapidjson::Value& histogram::report(rapidjson::Value &stat_value,
                                    rapidjson::Document::AllocatorType &allocator) {
	validate_snapshots();

	rapidjson::Value snapshots(rapidjson::kArrayType);
	snapshots.Reserve(m_snapshots.size(), allocator);
	for (auto it =  m_snapshots.begin(), end = m_snapshots.end(); it != end; ++it) {
		rapidjson::Value snapshot_value(rapidjson::kObjectType);
		snapshots.PushBack(print_data(snapshot_value, allocator, *it),
		                   allocator);
	}

	stat_value.AddMember("snapshots", snapshots, allocator);

	rapidjson::Value last_value(rapidjson::kObjectType);
	stat_value.AddMember("last_snapshot",
	                     print_data(last_value, allocator, m_last_data),
	                     allocator);

	clear_last();

	return stat_value;
}

void histogram::clear_last() {
	memset(m_last_data.counters.data(), 0, m_last_data.counters.size() * sizeof(m_last_data.counters.front()));
}

void histogram::validate_snapshots() {
	struct timeval timestamp;
	gettimeofday(&timestamp, NULL);

	auto delta_sec = std::min(size_t(timestamp.tv_sec - m_snapshots.rbegin()->timestamp.tv_sec),
	                          m_history_depth);

	if (delta_sec >= 1) {
		timestamp.tv_sec -= delta_sec - 1;
		for (size_t i = 0; i < delta_sec; ++i, ++timestamp.tv_sec) {
			m_snapshots.emplace_back(m_xs.size() * m_ys.size(), &timestamp);
		}

		for (auto size = m_snapshots.size(); size > m_history_depth; --size) {
			m_snapshots.erase(m_snapshots.begin());
		}
	}
}

std::vector<std::pair<uint64_t, std::string>> default_xs() {
	static std::vector<std::pair<uint64_t, std::string>> ret =
	{ std::make_pair<uint64_t, std::string>(500, "<500 usecs"),
	  std::make_pair<uint64_t, std::string>(5000, "<5000 usecs"),
	  std::make_pair<uint64_t, std::string>(100000, "<100000 usecs"),
	  std::make_pair<uint64_t, std::string>(100001, ">100000 usecs")};
	return ret;
}

std::vector<std::pair<uint64_t, std::string>> default_ys() {
	static std::vector<std::pair<uint64_t, std::string>> ret =
	{ std::make_pair<uint64_t, std::string>(100, "<100 bytes"),
	  std::make_pair<uint64_t, std::string>(500, "<500 bytes"),
	  std::make_pair<uint64_t, std::string>(1000, "<1000 bytes"),
	  std::make_pair<uint64_t, std::string>(1001, ">1000 bytes")};
	return ret;
}

}} /* namespace ioremap::monitor */
