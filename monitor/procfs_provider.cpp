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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "procfs_provider.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "elliptics/interface.h"

namespace ioremap { namespace monitor {

struct proc_io_stat {
	uint64_t rchar;
	uint64_t wchar;
	uint64_t syscr;
	uint64_t syscw;
	uint64_t read_bytes;
	uint64_t write_bytes;
	uint64_t cancelled_write_bytes;
};

static int fill_proc_io_stat(dnet_logger *l, struct proc_io_stat &st) {
	FILE *f;
	int err = 0;
	memset(&st, 0, sizeof(st));

	f = fopen("/proc/self/io", "r");
	if (!f) {
		err = -errno;
		dnet_log_write(l, DNET_LOG_ERROR, "Failed to open '/proc/self/io': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "rchar: %llu\n", (unsigned long long *)&st.rchar);
	err = fscanf(f, "wchar: %llu\n", (unsigned long long *)&st.wchar);
	err = fscanf(f, "syscr: %llu\n", (unsigned long long *)&st.syscr);
	err = fscanf(f, "syscw: %llu\n", (unsigned long long *)&st.syscw);
	err = fscanf(f, "read_bytes: %llu\n", (unsigned long long *)&st.read_bytes);
	err = fscanf(f, "write_bytes: %llu\n", (unsigned long long *)&st.write_bytes);
	err = fscanf(f, "cancelled_write_bytes: %llu\n", (unsigned long long *)&st.cancelled_write_bytes);

	fclose(f);
	err = 0;

err_out_exit:
	return err;
}

struct proc_stat {
	int threads_num;
	long rss;
	unsigned long vsize;
	unsigned long rsslim;
	unsigned long msize;
	unsigned long mresident;
	unsigned long mshare;
	unsigned long mcode;
	unsigned long mdata;
};

static int fill_proc_stat(dnet_logger *l, struct proc_stat &st) {
	int err = 0;
	FILE *f;
	memset(&st, 0, sizeof(st));

	f = fopen("/proc/self/stat", "r");
	if (!f) {
		err = -errno;
		dnet_log_write(l, DNET_LOG_ERROR, "Failed to open '/proc/self/stat': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	static const char f_str[] = "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %d %*d %*u %lu %ld %lu";

	err = fscanf(f, f_str, &st.threads_num, &st.vsize, &st.rss, &st.rsslim);
	fclose(f);

	f = fopen("/proc/self/statm", "r");
	if (!f) {
		err = -errno;
		dnet_log_write(l, DNET_LOG_ERROR, "Failed to open '/proc/self/statm': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%lu %lu %lu %lu %*u %lu", &st.msize, &st.mresident, &st.mshare, &st.mcode, &st.mdata);
	fclose(f);

	err = 0;

err_out_exit:
	return err;
}

struct net_stat {
	uint64_t bytes;
	uint64_t packets;
	uint64_t errors;
};

struct net_interface_stat {
	struct net_stat rx;
	struct net_stat tx;
};

static int fill_proc_net_stat(dnet_logger *l, std::map<std::string, net_interface_stat> &st)
{
	char buf[256] = {'\0'};
	net_interface_stat net_stat;
	FILE *f;
	int err = 0;

	f = fopen("/proc/net/dev", "r");
	if (!f) {
		dnet_log_write(l, DNET_LOG_ERROR, "Failed to open '/proc/net/dev': %s [%d].",
				  strerror(errno), errno);
		return -errno;
	}

	// skip first 2 headers
	for (int i = 0; i < 2; ++i) {
		if (!fgets(buf, sizeof(buf), f)) {
			dnet_log_write(l, DNET_LOG_ERROR, "could not read header on '/proc/net/dev'");
			err = -ENOENT;
			goto err_out_exit;
		}
	}

	while (1) {
		err = fscanf(f, "%255s %" PRIu64 " %" PRIu64 " %" PRIu64 " ""%*u %*u %*u %*u %*u "
				"%" PRIu64 " %" PRIu64 " %" PRIu64 " %*u %*u %*u %*u %*u", buf,
			     &net_stat.rx.bytes, &net_stat.rx.packets, &net_stat.rx.errors,
			     &net_stat.tx.bytes, &net_stat.tx.packets, &net_stat.tx.errors);
		if (err < 0) {
			if (ferror(f)) {
				dnet_log_write(l, DNET_LOG_ERROR, "fscanf failed on '/proc/net/dev': %s [%d].",
						  strerror(errno), errno);
				err = -errno;
				goto err_out_exit;
			} else {
				err = 0;
				break;
			}
		}

		buf[strlen(buf)-1] = '\0'; // erase ':' after interface name
		st.insert(std::make_pair(buf, net_stat));
	}

err_out_exit:
	fclose(f);
	return err;
}

procfs_provider::procfs_provider(struct dnet_node *node)
: m_node(node)
{}

static void fill_vm(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value vm_value(rapidjson::kObjectType);
	int err = 0;
	dnet_vm_stat st;

	err = dnet_get_vm_stat(node->log, &st);
	vm_value.AddMember("error", err, allocator);

	if (!err) {
		vm_value.AddMember("string_error", "", allocator);
		rapidjson::Value la_value(rapidjson::kArrayType);
		for (size_t i = 0; i < 3; ++i) {
			la_value.PushBack(st.la[i], allocator);
		}
		vm_value.AddMember("la", la_value, allocator);

		vm_value.AddMember("total", st.vm_total, allocator);
		vm_value.AddMember("active", st.vm_active, allocator);
		vm_value.AddMember("inactive", st.vm_inactive, allocator);
		vm_value.AddMember("free", st.vm_free, allocator);
		vm_value.AddMember("cached", st.vm_cached, allocator);
		vm_value.AddMember("buffers", st.vm_buffers, allocator);
	} else
		vm_value.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("vm", vm_value, allocator);
}

static void fill_io(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value io_stat(rapidjson::kObjectType);
	int err = 0;
	proc_io_stat st;

	err = fill_proc_io_stat(node->log, st);
	io_stat.AddMember("error", err, allocator);

	if (!err) {
		io_stat.AddMember("string_error", "", allocator);
		io_stat.AddMember("rchar", st.rchar, allocator);
		io_stat.AddMember("wchar", st.wchar, allocator);
		io_stat.AddMember("syscr", st.syscr, allocator);
		io_stat.AddMember("syscw", st.syscw, allocator);
		io_stat.AddMember("read_bytes", st.read_bytes, allocator);
		io_stat.AddMember("write_bytes", st.write_bytes, allocator);
		io_stat.AddMember("cancelled_write_bytes", st.cancelled_write_bytes, allocator);
	} else
		io_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("io", io_stat, allocator);
}

static void fill_stat(dnet_node *node,
                      rapidjson::Value &stat_value,
                      rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value stat_stat(rapidjson::kObjectType);
	int err = 0;
	proc_stat st;

	err = fill_proc_stat(node->log, st);
	stat_stat.AddMember("error", err, allocator);

	if (!err) {
		stat_stat.AddMember("string_error", "", allocator);
		stat_stat.AddMember("threads_num", st.threads_num, allocator);
		stat_stat.AddMember("rss", (int64_t)st.rss, allocator);
		stat_stat.AddMember("vsize", (uint64_t)st.vsize, allocator);
		stat_stat.AddMember("rsslim", (uint64_t)st.rsslim, allocator);
		stat_stat.AddMember("msize", (uint64_t)st.msize, allocator);
		stat_stat.AddMember("mresident", (uint64_t)st.mresident, allocator);
		stat_stat.AddMember("mshare", (uint64_t)st.mshare, allocator);
		stat_stat.AddMember("mcode", (uint64_t)st.mcode, allocator);
		stat_stat.AddMember("mdata", (uint64_t)st.mdata, allocator);
	} else
		stat_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("stat", stat_stat, allocator);
}

static void fill_net_stat(const char *origin,
			  const struct net_stat &ns,
			  rapidjson::Value &stat_value,
			  rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value stat(rapidjson::kObjectType);
	stat.AddMember("bytes", ns.bytes, allocator);
	stat.AddMember("packets", ns.packets, allocator);
	stat.AddMember("errors", ns.errors, allocator);
	stat_value.AddMember(origin, stat, allocator);
}

static void fill_net(dnet_node *node,
                     rapidjson::Value &stat_value,
                     rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value net_stat(rapidjson::kObjectType);
	int err = 0;
	std::map<std::string, net_interface_stat> st;

	err = fill_proc_net_stat(node->log, st);
	net_stat.AddMember("error", err, allocator);

	if (!err) {
		rapidjson::Value dev_stat(rapidjson::kObjectType);

		for (auto it = st.cbegin(); it != st.cend(); ++it) {
			rapidjson::Value stat(rapidjson::kObjectType);

			const std::string &name = it->first;
			const net_interface_stat &ns = it->second;

			fill_net_stat("receive", ns.rx, stat, allocator);
			fill_net_stat("transmit", ns.tx, stat, allocator);

			dev_stat.AddMember(name.c_str(), allocator, stat, allocator);
		}

		net_stat.AddMember("string_error", "", allocator);
		net_stat.AddMember("net_interfaces", dev_stat, allocator);
	} else
		net_stat.AddMember("string_error", strerror(-err), allocator);

	stat_value.AddMember("net", net_stat, allocator);
}

std::string procfs_provider::json(uint64_t categories) const {
	if (!(categories & DNET_MONITOR_PROCFS))
	    return std::string();

	rapidjson::Document doc;
	doc.SetObject();
	auto &allocator = doc.GetAllocator();

	fill_vm(m_node, doc, allocator);
	fill_io(m_node, doc, allocator);
	fill_stat(m_node, doc, allocator);
	fill_net(m_node, doc, allocator);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}


}} /* namespace ioremap::monitor */
