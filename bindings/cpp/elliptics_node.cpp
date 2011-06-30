/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"

#define _XOPEN_SOURCE 600

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sstream>
#include <stdexcept>

#include "elliptics/cppdef.h"

using namespace zbr;

elliptics_node::elliptics_node(elliptics_log &l)
{
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 5;
	cfg.check_timeout = 20;

	log = reinterpret_cast<elliptics_log *>(l.clone());
	cfg.log = log->get_dnet_log();

	snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
	snprintf(cfg.port, sizeof(cfg.port), "0");

	node = dnet_node_create(&cfg);
	if (!node) {
		delete log;
		throw std::bad_alloc();
	}
}

elliptics_node::elliptics_node(elliptics_log &l, struct dnet_config &cfg)
{
	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;

	log = reinterpret_cast<elliptics_log *>(l.clone());
	cfg.log = log->get_dnet_log();

	snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
	snprintf(cfg.port, sizeof(cfg.port), "0");

	node = dnet_node_create(&cfg);
	if (!node) {
		delete log;
		throw std::bad_alloc();
	}
}

elliptics_node::~elliptics_node()
{
	dnet_node_destroy(node);
	delete log;
}

void elliptics_node::add_groups(std::vector<int> &groups)
{
	if (dnet_node_set_groups(node, (int *)&groups[0], groups.size()))
		throw std::bad_alloc();
	this->groups = groups;
}

void elliptics_node::add_remote(const char *addr, const int port, const int family)
{
	struct dnet_config cfg;
	int err;

	memset(&cfg, 0, sizeof(cfg));

	cfg.family = family;
	snprintf(cfg.addr, sizeof(cfg.addr), "%s", addr);
	snprintf(cfg.port, sizeof(cfg.port), "%d", port);

	err = dnet_add_state(node, &cfg);
	if (err) {
		std::ostringstream str;
		str << "Failed to add remote addr " << addr << ":" << port << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::read_file(struct dnet_id &id, const std::string &file, uint64_t offset, uint64_t size)
{
	int err;

	err = dnet_read_file_id(node, file.c_str(), &id, offset, size);
	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: " << file << ": offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::read_file(const std::string &remote, const std::string &file, uint64_t offset, uint64_t size, int type)
{
	int err;

	err = dnet_read_file(node, file.c_str(), remote.data(), remote.size(), offset, size, type);
	if (err) {
		struct dnet_id id;
		transform(remote, id);

		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: " << file << ": offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::write_file(struct dnet_id &id, const std::string &file, uint64_t local_offset,
		uint64_t offset, uint64_t size, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_id(node, file.c_str(), &id, local_offset, offset, size, aflags, ioflags);
	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": WRITE: " << file << ", local_offset: " << local_offset <<
			", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}
void elliptics_node::write_file(const std::string &remote, const std::string &file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags, int type)
{
	int err = dnet_write_file(node, file.c_str(), remote.data(), remote.size(),
			local_offset, offset, size, aflags, ioflags, type);
	if (err) {
		struct dnet_id id;
		transform(remote, id);

		std::ostringstream str;
		str << dnet_dump_id(&id) << ": WRITE: " << file << ", local_offset: " << local_offset <<
			", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

std::string elliptics_node::read_data_wait(struct dnet_id &id, uint64_t offset, uint64_t size,
		uint32_t aflags, uint32_t ioflags)
{
	struct dnet_io_attr io;
	int err;

	memset(&io, 0, sizeof(io));
	io.size = size;
	io.offset = offset;
	io.flags = ioflags;

	id.type = io.type;

	void *data = dnet_read_data_wait(node, &id, &io, aflags, &err);
	if (!data) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: size: " << size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::string ret = std::string((const char *)data + sizeof(struct dnet_io_attr), io.size - sizeof(struct dnet_io_attr));
	free(data);

	return ret;
}

std::string elliptics_node::read_data_wait(const std::string &remote, uint64_t offset, uint64_t size,
		uint32_t aflags, uint32_t ioflags, int type)
{
	struct dnet_id id;

	transform(remote, id);
	id.type = type;

	return read_data_wait(id, size, offset, aflags, ioflags);
}

int elliptics_node::write_data_wait(struct dnet_id &id, const std::string &str,
		uint64_t remote_offset, unsigned int aflags, unsigned int ioflags)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.aflags = aflags;
	ctl.data = str.data();

	ctl.io.flags = ioflags;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = id.type;

	ctl.fd = -1;

	int err = dnet_write_data_wait(node, &ctl);
	if (err < 0) {
		std::ostringstream string;
		string << dnet_dump_id(&id) << ": WRITE: size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}
	return err;
}

int elliptics_node::write_data_wait(const std::string &remote, const std::string &str,
		uint64_t remote_offset, unsigned int aflags, unsigned int ioflags, int type)
{
	struct dnet_id id;

	transform(remote, id);
	id.type = type;

	return write_data_wait(id, str, remote_offset, aflags, ioflags);
}

std::string elliptics_node::lookup_addr(const std::string &remote, const int group_id)
{
	char buf[128];

	int err = dnet_lookup_addr(node, remote.data(), remote.size(), NULL, group_id, buf, sizeof(buf));
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to lookup in group " << group_id << ": key size: " << remote.size() << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)buf, strlen(buf));
}

std::string elliptics_node::lookup_addr(const struct dnet_id &id)
{
	char buf[128];

	int err = dnet_lookup_addr(node, NULL, 0, (struct dnet_id *)&id, id.group_id, buf, sizeof(buf));
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to lookup " << dnet_dump_id(&id) << ": err: " << err;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)buf, strlen(buf));
}


int elliptics_node::write_metadata(const struct dnet_id &id, const std::string &obj, const std::vector<int> &groups, const struct timespec &ts)
{
	int err;
	struct dnet_metadata_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.obj = (char *)obj.data();
	ctl.len = obj.size();
	
	ctl.groups = (int *)&groups[0];
	ctl.group_num = groups.size();

	ctl.ts = ts;
	ctl.id = id;

	err = dnet_create_write_metadata(node, &ctl);
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to write metadata: key: " << dnet_dump_id(&id) << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	return err;
}
		
void elliptics_node::transform(const std::string &data, struct dnet_id &id)
{
	dnet_transform(node, (void *)data.data(), data.size(), &id);
}

void elliptics_node::lookup(const struct dnet_id &id, const elliptics_callback &c)
{
	int err = dnet_lookup_object(node, (struct dnet_id *)&id, 0,
			elliptics_callback::elliptics_complete_callback,
			(void *)&c);

	if (err) {
		std::ostringstream str;
		str << "Failed to lookup ID " << dnet_dump_id(&id) << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::lookup(const std::string &data, const elliptics_callback &c)
{
	struct dnet_id id;
	int error = -ENOENT, i, num, *g;

	transform(data, id);

	num = dnet_mix_states(node, &id, &g);
	if (num < 0)
		throw std::bad_alloc();

	for (i=0; i<num; ++i) {
		id.group_id = g[i];

		try {
			lookup(id, c);
		} catch (...) {
			continue;
		}

		error = 0;
		break;
	}

	free(g);

	if (error) {
		std::ostringstream str;
		str << "Failed to lookup data object: key: " << dnet_dump_id(&id);
		throw std::runtime_error(str.str());
	}
}

std::string elliptics_node::lookup(const std::string &data)
{
	struct dnet_id id;
	int error = -ENOENT, i, num, *g;
	std::string ret;

	transform(data, id);

	num = dnet_mix_states(node, &id, &g);
	if (num < 0)
		throw std::bad_alloc();

	for (i=0; i<num; ++i) {
		try {
			elliptics_callback l;
			id.group_id = g[i];

			lookup(id, l);
			ret = l.wait();

			if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + sizeof(struct dnet_attr)) {
				std::stringstream str;

				str << dnet_dump_id(&id) << ": failed to receive lookup request";
				throw std::runtime_error(str.str());
			}
#if 0
			struct dnet_addr *addr = (struct dnet_addr *)ret.data();
			struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
			struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);

			if (attr->size > sizeof(struct dnet_addr_attr)) {
				struct dnet_addr_attr *a = (struct dnet_addr_attr *)(attr + 1);
				struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

				dnet_convert_addr_attr(a);
				dnet_convert_file_info(info);
			}
#endif
			dnet_log_raw(node, DNET_LOG_DSA, "%s: %s: %zu bytes\n", dnet_dump_id(&id), data.c_str(), ret.size());
			error = 0;
			break;
		} catch (const std::exception &e) {
			dnet_log_raw(node, DNET_LOG_ERROR, "%s: %s : %s\n", dnet_dump_id(&id), e.what(), data.c_str());
			continue;
		}
	}

	free(g);

	if (error) {
		std::ostringstream str;
		str << data << ": could not find object";

		throw std::runtime_error(str.str());
	}

	return ret;
}

void elliptics_node::remove(struct dnet_id &id)
{
	int err = dnet_remove_object_now(node, &id, 0);

	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": REMOVE: " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::remove(const std::string &data, int type)
{
	struct dnet_id id;
	int err = -ENOENT, i;
	std::vector<int> g = groups;

	transform(data, id);
	id.type = type;

	for (i=0; i<(int)g.size(); ++i) {
		id.group_id = g[i];

		try {
			remove(id);
		} catch (const std::exception &e) {
			continue;
		}

		err = 0;
	}

	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": REMOVE: " << data << err;
		throw std::runtime_error(str.str());
	}
}

std::string elliptics_node::stat_log()
{
	elliptics_callback c;
	std::string ret;
	int err;

	err = dnet_request_stat(node, NULL, DNET_CMD_STAT, 0,
		elliptics_callback::elliptics_complete_callback, (void *)&c);
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to request statistics: " << err;
		throw std::runtime_error(str.str());
	}

	ret = c.wait(err);
#if 0
	float la[3];
	const void *data = ret.data();
	int size = ret.size();
	char id_str[DNET_ID_SIZE*2 + 1];
	char addr_str[128];

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_attr *attr = (struct dnet_attr *)(cmd + 1);
		struct dnet_stat *st = (struct dnet_stat *)(attr + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		printf("<stat addr=\"%s\" id=\"%s\"><la>%.2f %.2f %.2f</la>"
				"<memtotal>%llu KB</memtotal><memfree>%llu KB</memfree><memcached>%llu KB</memcached>"
				"<storage_size>%llu MB</storage_size><available_size>%llu MB</available_size>"
				"<files>%llu</files><fsid>0x%llx</fsid></stat>",
				dnet_server_convert_dnet_addr_raw(addr, addr_str, sizeof(addr_str)),
				dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str),
				la[0], la[1], la[2],
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached,
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
		printf("\n");

		int sz = sizeof(*addr) + sizeof(*cmd) + sizeof(*attr) + attr->size;

		size -= sz;
		data += sz;
	}
#endif

	if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + sizeof(struct dnet_stat))
		throw std::runtime_error("Failed to request statistics: not enough data returned");
	return ret;
}

int elliptics_node::state_num(void)
{
	return dnet_state_num(node);
}

int elliptics_node::request_cmd(struct dnet_trans_control &ctl)
{
	int err;

	err = dnet_request_cmd(node, &ctl);
	if (err < 0) {
		std::ostringstream str;
		str << dnet_dump_id(&ctl.id) << ": failed to request cmd: " << dnet_cmd_string(ctl.cmd) << ": " << err;
		throw std::runtime_error(str.str());
	}

	return err;
}

void elliptics_node::update_status(const char *saddr, const int port, const int family, struct dnet_node_status *status, int update)
{
	int err;
	struct dnet_addr addr;
	char sport[16];

	memset(&addr, 0, sizeof(addr));
	addr.addr_len = sizeof(addr.addr);

	snprintf(sport, sizeof(sport), "%d", port);

	err = dnet_fill_addr(&addr, saddr, sport, family, SOCK_STREAM, IPPROTO_TCP);
	if (!err)
		err = dnet_update_status(node, &addr, NULL, status, update);

	if (err < 0) {
		std::ostringstream str;
		str << saddr << ":" << port << ": failed to request set status " << std::hex << status << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::update_status(struct dnet_id &id, struct dnet_node_status *status, int update)
{
	int err;

	err = dnet_update_status(node, NULL, &id, status, update);
	if (err < 0) {
		std::ostringstream str;

		str << dnet_dump_id(&id) << ": failed to request set status " << std::hex << status << ": " << err;
		throw std::runtime_error(str.str());
	}
}

std::string elliptics_node::read_data_range(struct dnet_io_attr &io, int group_id, uint32_t aflags)
{
	struct dnet_range_data *data;
	int err;

	data = dnet_read_range(node, &io, group_id, aflags, &err);
	if (!data) {
		std::ostringstream str;
		str << "Failed to read range data object: group: " << group_id <<
			", key: " << dnet_dump_id_str(io.id) <<
			", size: " << io.size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::string ret;

	for (int i = 0; i < err; ++i) {
		struct dnet_range_data *d = &data[i];

		ret.append((const char *)d->data, d->size);
		free(d->data);
	}

	free(data);

	return ret;
}
