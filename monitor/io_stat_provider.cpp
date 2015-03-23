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

#include "io_stat_provider.hpp"

#include "library/elliptics.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {

void dump_list_stats(rapidjson::Value &stat, list_stat &list_stats, rapidjson::Document::AllocatorType &allocator) {
	stat.AddMember("current_size", list_stats.list_size, allocator);
}

void dump_states_stats(rapidjson::Value &stat, struct dnet_node *n, rapidjson::Document::AllocatorType &allocator) {
	struct dnet_net_state *st;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->empty_state_list, node_entry) {
		rapidjson::Value state_value(rapidjson::kObjectType);
		state_value.AddMember("send_queue_size", atomic_read(&st->send_queue_size), allocator)
		           .AddMember("la", st->la, allocator)
		           .AddMember("free", (uint64_t)st->free, allocator)
		           .AddMember("weight", st->weight, allocator)
		           .AddMember("stall", st->stall, allocator)
		           .AddMember("join_state", st->__join_state, allocator);

		rapidjson::Value addr(dnet_addr_string(&st->addr), allocator);
		stat.AddMember(addr, state_value, allocator);
	}
	pthread_mutex_unlock(&n->state_lock);
}

std::string io_stat_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_IO))
		return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	rapidjson::Value blocking_stat(rapidjson::kObjectType);
	dump_list_stats(blocking_stat, m_node->io->pool.recv_pool.pool->list_stats, allocator);
	doc.AddMember("blocking", blocking_stat, allocator);

	rapidjson::Value nonblocking_stat(rapidjson::kObjectType);
	dump_list_stats(nonblocking_stat, m_node->io->pool.recv_pool_nb.pool->list_stats, allocator);
	doc.AddMember("nonblocking", nonblocking_stat, allocator);

	rapidjson::Value output_stat(rapidjson::kObjectType);
	dump_list_stats(output_stat, m_node->io->output_stats, allocator);
	doc.AddMember("output", output_stat, allocator);

	rapidjson::Value states_stat(rapidjson::kObjectType);
	dump_states_stats(states_stat, m_node, allocator);
	doc.AddMember("states", states_stat, allocator);

	doc.AddMember("blocked", m_node->io->blocked == 1, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}

}} /* namespace ioremap::monitor */
