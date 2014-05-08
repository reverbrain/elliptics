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

react_stat_provider::react_stat_provider() {
}

std::string react_stat_provider::json() const {
	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	{
		std::lock_guard<std::mutex> guard(react_aggregator.mutex);
		rapidjson::Value aggregator_value(rapidjson::kArrayType);
		for (auto it = react_aggregator.recent_call_trees.begin(); it != react_aggregator.recent_call_trees.end(); ++it) {
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

bool react_stat_provider::check_category(int category) const {
	return category == DNET_MONITOR_CALL_TREE || category == DNET_MONITOR_ALL;
}

react::elliptics_react_aggregator_t &react_stat_provider::get_react_aggregator() {
	return react_aggregator;
}

}} /* namespace ioremap::monitor */
