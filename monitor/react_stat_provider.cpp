/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
 * Copyright 2013+ Andrey Kashin <kashin.andrej@gmail.com>
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

#include "react_stat_provider.hpp"

#include "library/elliptics.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {

react_stat_provider::react_stat_provider(uint32_t call_timeout)
: m_call_timeout(call_timeout) {
}

int64_t call_tree_time(const react::call_tree_t &tree) {
	std::chrono::microseconds ts(tree.get_node_stop_time(tree.root) - tree.get_node_start_time(tree.root));
	return std::chrono::duration_cast<std::chrono::seconds>(ts).count();
}

std::string react_stat_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_CALL_TREE))
		return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	{
		std::lock_guard<std::mutex> guard(react_aggregator.mutex);
		rapidjson::Value aggregator_value(rapidjson::kArrayType);
		for (auto it = react_aggregator.recent_call_trees.begin(); it != react_aggregator.recent_call_trees.end(); ++it) {
			if (call_tree_time(*it) < m_call_timeout)
				continue;
			rapidjson::Value tree_value(rapidjson::kObjectType);
			(*it).to_json(tree_value, allocator);
			aggregator_value.PushBack(tree_value, allocator);
		}
		doc.AddMember("react_aggregator", aggregator_value, allocator);
	}

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

react::elliptics_react_aggregator_t &react_stat_provider::get_react_aggregator() {
	return react_aggregator;
}

}} /* namespace ioremap::monitor */
