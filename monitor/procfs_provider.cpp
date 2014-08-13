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

#include "procfs_provider.hpp"

#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace ioremap { namespace monitor {

struct vm_stat {
	uint16_t		la[3];
	uint64_t		vm_active;
	uint64_t		vm_inactive;
	uint64_t		vm_total;
	uint64_t		vm_free;
	uint64_t		vm_cached;
	uint64_t		vm_buffers;
};

#if defined HAVE_PROC_STAT
static int fill_vm_stat(dnet_logger *l, struct vm_stat &st) {
	int err;
	FILE *f;
	float la[3];
	unsigned long long stub;

	f = fopen("/proc/loadavg", "r");
	if (!f) {
		err = -errno;
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to open '/proc/loadavg': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%f %f %f", &la[0], &la[1], &la[2]);
	if (err != 3) {
		err = -errno;
		if (!err)
			err = -EINVAL;

		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to read load average data: %s [%d].",
		                 strerror(errno), errno);
		goto err_out_close;
	}

	st.la[0] = la[0] * 100;
	st.la[1] = la[1] * 100;
	st.la[2] = la[2] * 100;

	fclose(f);

	f = fopen("/proc/meminfo", "r");
	if (!f) {
		err = -errno;
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to open '/proc/meminfo': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "MemTotal:%llu kB\n", (unsigned long long *)&st.vm_total);
	err = fscanf(f, "MemFree:%llu kB\n", (unsigned long long *)&st.vm_free);
	err = fscanf(f, "Buffers:%llu kB\n", (unsigned long long *)&st.vm_buffers);
	err = fscanf(f, "Cached:%llu kB\n", (unsigned long long *)&st.vm_cached);
	err = fscanf(f, "SwapCached:%llu kB\n", (unsigned long long *)&stub);
	err = fscanf(f, "Active:%llu kB\n", (unsigned long long *)&st.vm_active);
	err = fscanf(f, "Inactive:%llu kB\n", (unsigned long long *)&st.vm_inactive);

	fclose(f);
	return 0;

err_out_close:
	fclose(f);
err_out_exit:
	return err;
}
#elif defined HAVE_SYSCTL_STAT
#include <sys/sysctl.h>
#include <sys/resource.h>

static int fill_vm_stat(dnet_logger *l, struct vm_stat &st) {
	int err;
	struct loadavg la;
	long page_size = 0;
	size_t sz = sizeof(la);

	err = sysctlbyname("vm.loadavg", &la, &sz, NULL, 0);
	if (err) {
		err = -errno;
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to get load average data: %s [%d].",
				strerror(errno), errno);
		return err;
	}

	st.la[0] = (double)la.ldavg[0] / la.fscale * 100;
	st.la[1] = (double)la.ldavg[1] / la.fscale * 100;
	st.la[2] = (double)la.ldavg[2] / la.fscale * 100;

	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_active_count", &st.vm_active, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_inactive_count", &st.vm_inactive, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_cache_count", &st.vm_cached, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_free_count", &st.vm_free, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_wire_count", &st.vm_buffers, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_page_count", &st.vm_total, &sz, NULL, 0);
	sz = sizeof(page_size);
	sysctlbyname("vm.stats.vm.v_page_size", &page_size, &sz, NULL, 0);

	page_size /= 1024;

	st->vm_total *= page_size;
	st->vm_active *= page_size;
	st->vm_inactive *= page_size;
	st->vm_free *= page_size;
	st->vm_cached *= page_size;
	st->vm_buffers *= page_size;

	return 0;
}
#else
static int fill_vm_stat(dnet_logger *l __unused, struct vm_stat &st __unused) {
	return 0;
}
#endif

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
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to open '/proc/self/io': %s [%d].",
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
	long threads_num;
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
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to open '/proc/self/stat': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	static const char f_str[] = "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu %*lu %*lu %*ld %*ld %*ld %*ld %ld %*ld %*llu %lu %ld %lu";

	err = fscanf(f, f_str, &st.threads_num, &st.vsize, &st.rss, &st.rsslim);
	fclose(f);

	f = fopen("/proc/self/statm", "r");
	if (!f) {
		err = -errno;
		dnet_backend_log(l, DNET_LOG_ERROR, "Failed to open '/proc/self/statm': %s [%d].",
		                 strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%lu %lu %lu %lu %*u %lu", &st.msize, &st.mresident, &st.mshare, &st.mcode, &st.mdata);
	fclose(f);

	err = 0;

err_out_exit:
	return err;
}

procfs_provider::procfs_provider(struct dnet_node *node)
: m_node(node)
{}

static void fill_vm(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	vm_stat st;
	if (fill_vm_stat(node->log, st))
		return;

	rapidjson::Value vm_value(rapidjson::kObjectType);

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

	stat_value.AddMember("vm", vm_value, allocator);
}

static void fill_io(dnet_node *node,
                    rapidjson::Value &stat_value,
                    rapidjson::Document::AllocatorType &allocator) {
	proc_io_stat st;
	if (fill_proc_io_stat(node->log, st))
		return;

	rapidjson::Value io_stat(rapidjson::kObjectType);

	io_stat.AddMember("rchar", st.rchar, allocator);
	io_stat.AddMember("wchar", st.wchar, allocator);
	io_stat.AddMember("syscr", st.syscr, allocator);
	io_stat.AddMember("syscw", st.syscw, allocator);
	io_stat.AddMember("read_bytes", st.read_bytes, allocator);
	io_stat.AddMember("write_bytes", st.write_bytes, allocator);
	io_stat.AddMember("cancelled_write_bytes", st.cancelled_write_bytes, allocator);

	stat_value.AddMember("io", io_stat, allocator);
}

static void fill_stat(dnet_node *node,
                      rapidjson::Value &stat_value,
                      rapidjson::Document::AllocatorType &allocator) {
	rapidjson::Value stat_stat(rapidjson::kObjectType);

	proc_stat st;
	if (fill_proc_stat(node->log, st))
		return;

	stat_stat.AddMember("threads_num", st.threads_num, allocator);
	stat_stat.AddMember("rss", st.rss, allocator);
	stat_stat.AddMember("vsize", st.vsize, allocator);
	stat_stat.AddMember("rsslim", st.rsslim, allocator);
	stat_stat.AddMember("msize", st.msize, allocator);
	stat_stat.AddMember("mresident", st.mresident, allocator);
	stat_stat.AddMember("mshare", st.mshare, allocator);
	stat_stat.AddMember("mcode", st.mcode, allocator);
	stat_stat.AddMember("mdata", st.mdata, allocator);

	stat_value.AddMember("stat", stat_stat, allocator);
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

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	doc.Accept(writer);
	return buffer.GetString();
}


}} /* namespace ioremap::monitor */
