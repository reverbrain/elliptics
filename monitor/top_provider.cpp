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

#include "library/elliptics.h"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "elliptics/interface.h"

namespace ioremap { namespace monitor {

top_provider::top_provider(struct dnet_node *node, size_t events_limit, int period_in_seconds)
: m_node(node),
 m_stats(events_limit, period_in_seconds)
{}

static void fill_stat__(dnet_node *node,
                      rapidjson::Value &stat_value,
                      rapidjson::Document::AllocatorType &allocator) {
	/*rapidjson::Value stat_stat(rapidjson::kObjectType);
	int err = 0;
	proc_stat st;

	err = fill_proc_stat(node->log, st);
	stat_stat.AddMember("error", err, allocator);

	if (!err) {
		stat_stat.AddMember("string_error", "", allocator);
		stat_stat.AddMember("threads_num", st.threads_num, allocator);
		stat_stat.AddMember("rss", st.rss, allocator);
		stat_stat.AddMember("vsize", st.vsize, allocator);
		stat_stat.AddMember("rsslim", st.rsslim, allocator);
		stat_stat.AddMember("msize", st.msize, allocator);
		stat_stat.AddMember("mresident", st.mresident, allocator);
		stat_stat.AddMember("mshare", st.mshare, allocator);
		stat_stat.AddMember("mcode", st.mcode, allocator);
		stat_stat.AddMember("mdata", st.mdata, allocator);
	} else
		stat_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("stat", stat_stat, allocator);*/
}

std::string top_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_TOP))
		return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	fill_stat__(m_node, doc, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

void top_provider::update_stats(struct dnet_cmd *cmd, uint64_t size)
{
	key_stat_event event{cmd->id, size, time(nullptr)};
	m_stats.add_event(event, event.get_time());
}

}} /* namespace ioremap::monitor */


// if more than top keys statistics measured, then move this function implementation
// to a separate unit (e.g. node_stats.{hpp,cpp}), because this unit shouldn't depend
// on other headers (other than top_provider.hpp)
void dnet_node_stats_update(struct dnet_node *node, struct dnet_cmd *cmd, uint64_t size)
{
	typedef ioremap::monitor::monitor* MonitorPtr;
	typedef std::shared_ptr<ioremap::monitor::stat_provider> StatPtr;
	typedef std::shared_ptr<ioremap::monitor::top_provider> TopStatPtr;

	MonitorPtr monitor = reinterpret_cast<MonitorPtr>(node->monitor);
	if (monitor == nullptr)
		return;

	StatPtr provider = monitor->get_statistics().get_provider("top");
	if (provider) {
		TopStatPtr top_provider = std::dynamic_pointer_cast<ioremap::monitor::top_provider>(provider);
		assert(top_provider != nullptr);

		top_provider->update_stats(cmd, size);
	}
}
