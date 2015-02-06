/*
 * Copyright 2015+ Budnik Andrey <budnik27@gmail.com>
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

#include "top_provider.hpp"
#include "monitor.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "elliptics/interface.h"

namespace ioremap { namespace monitor {

top_provider::top_provider(struct dnet_node *node)
: m_node(node)
{
	auto monitor = get_monitor(node);
	m_top_stats = monitor->get_top_stats();
}

static inline char *dnet_dump_id_str_full(const unsigned char *id)
{
	static __thread char __dnet_dump_id_str_full[2 * DNET_ID_SIZE + 1];
	return dnet_dump_id_len_raw(id, DNET_ID_SIZE, __dnet_dump_id_str_full);
}

static void fill_top_stat(const key_stat_event &key_event,
                      rapidjson::Value &stat_array,
                      rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value key_stat(rapidjson::kObjectType);

	key_stat.AddMember("group", key_event.get_key()->group_id, allocator);
	rapidjson::Value id;
	id.SetString(dnet_dump_id_str_full(key_event.get_key()->id), allocator);
	key_stat.AddMember("id", id, allocator);
	key_stat.AddMember("size", key_event.get_weight(), allocator);
	key_stat.AddMember("frequency", static_cast<uint64_t>(key_event.get_frequency()), allocator);

	stat_array.PushBack(key_stat, allocator);
}

std::string top_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_TOP))
		return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	std::vector<key_stat_event> top_size_keys;
	auto& event_stats = m_top_stats->get_stats();
	event_stats.get_top(m_top_stats->get_top_k(), time(nullptr), top_size_keys);

	rapidjson::Value stat_array(rapidjson::kArrayType);
	stat_array.Reserve(top_size_keys.size(), allocator);

	for (auto it = top_size_keys.cbegin(); it != top_size_keys.cend(); ++it) {
		const auto &key_stat = *it;
		fill_top_stat(key_stat, stat_array, allocator);
	}

	doc.AddMember("top_by_size", stat_array, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

}} /* namespace ioremap::monitor */
