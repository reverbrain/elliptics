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

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <elliptics/cppdef.h>

using namespace ioremap::elliptics;

node::node(logger &l) : m_node(NULL), m_log(NULL)
{
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 5;
	cfg.check_timeout = 20;

	m_log = reinterpret_cast<logger *>(l.clone());
	cfg.log = m_log->get_dnet_log();

	snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
	snprintf(cfg.port, sizeof(cfg.port), "0");

	m_node = dnet_node_create(&cfg);
	if (!m_node) {
		delete m_log;
		throw std::bad_alloc();
	}
}

node::node(logger &l, struct dnet_config &cfg) : m_node(NULL), m_log(NULL)
{
	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;

	m_log = reinterpret_cast<logger *>(l.clone());
	cfg.log = m_log->get_dnet_log();

	snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
	snprintf(cfg.port, sizeof(cfg.port), "0");

	m_node = dnet_node_create(&cfg);
	if (!m_node) {
		delete m_log;
		throw std::bad_alloc();
	}
}

node::node(logger &l, const std::string &config_path) : m_node(NULL), m_log(NULL)
{
	struct dnet_config cfg;
	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;

	m_log = reinterpret_cast<logger *>(l.clone());
	cfg.log = m_log->get_dnet_log();

	std::list<addr_tuple> remotes;
	std::vector<int> groups;

	parse_config(config_path, cfg, remotes, groups, cfg.log->log_mask);

	m_node = dnet_node_create(&cfg);
	if (!m_node) {
		delete m_log;
		throw std::bad_alloc();
	}

	add_groups(groups);
	for (std::list<addr_tuple>::iterator it = remotes.begin(); it != remotes.end(); ++it) {
		try {
			add_remote(it->host.c_str(), it->port, it->family);
		} catch (...) {
			continue;
		}
	}
}

node::~node()
{
	dnet_node_destroy(m_node);
	delete m_log;
}

void node::parse_config(const std::string &path, struct dnet_config &cfg,
		std::list<addr_tuple> &remotes,
		std::vector<int> &groups,
		uint32_t &log_mask)
{
	std::ifstream in(path.c_str());
	std::string line;
	int line_num = 0;

	while (!in.eof() && in.good()) {
		line.resize(1024);

		in.getline((char *)line.data(), line.size());
		size_t len = in.gcount();

		line.resize(len);

		if (in.eof() || !in.good())
			break;

		boost::trim(line);
		line_num++;

		if (line.size() < 3 || line.data()[0] == '#')
			continue;

		std::vector<std::string> strs;
		boost::split(strs, line, boost::is_any_of("="));

		std::string key = strs[0];
		boost::trim(key);

		if (strs.size() != 2) {
			std::ostringstream str;
			str << path << ": invalid elliptics config: line: " << line_num <<
				", key: " << key << "': string is broken: size: " << strs.size();
			throw std::runtime_error(str.str());
		}
		std::string value = strs[1];
		boost::trim(value);

		if (key == "remote") {
			std::vector<std::string> rem;
			boost::split(rem, value, boost::is_any_of(" "));

			for (std::vector<std::string>::iterator it = rem.begin(); it != rem.end(); ++it) {
				std::string addr_str = *it;
				if (dnet_parse_addr((char *)addr_str.c_str(), &cfg)) {
					std::ostringstream str;
					str << path << ": invalid elliptics config: '" << key << "' ";
					str << path << ": invalid elliptics config: line: " << line_num <<
						", key: '" << key << "': remote addr is invalid";
					throw std::runtime_error(str.str());
				}

				addr_tuple addr(cfg.addr, atoi(cfg.port), cfg.family);
				remotes.push_back(addr);
			}
		}

		if (key == "groups") {
			std::vector<std::string> gr;
			boost::split(gr, value, boost::is_any_of(":"));

			for (std::vector<std::string>::iterator it = gr.begin(); it != gr.end(); ++it) {
				int group = atoi(it->c_str());

				if (group != 0)
					groups.push_back(group);
			}
		}

		if (key == "check_timeout")
			cfg.check_timeout = strtoul(value.c_str(), NULL, 0);
		if (key == "wait_timeout")
			cfg.wait_timeout = strtoul(value.c_str(), NULL, 0);
		if (key == "log_mask")
			log_mask = strtoul(value.c_str(), NULL, 0);
	}
}

void node::add_groups(std::vector<int> &groups)
{
	if (dnet_node_set_groups(m_node, (int *)&groups[0], groups.size()))
		throw std::bad_alloc();
	this->groups = groups;
}

void node::add_remote(const char *addr, const int port, const int family)
{
	struct dnet_config cfg;
	int err;

	memset(&cfg, 0, sizeof(cfg));

	cfg.family = family;
	snprintf(cfg.addr, sizeof(cfg.addr), "%s", addr);
	snprintf(cfg.port, sizeof(cfg.port), "%d", port);

	err = dnet_add_state(m_node, &cfg);
	if (err) {
		std::ostringstream str;
		str << "Failed to add remote addr " << addr << ":" << port << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void node::read_file(struct dnet_id &id, const std::string &file, uint64_t offset, uint64_t size)
{
	int err;

	err = dnet_read_file_id(m_node, file.c_str(), &id, offset, size);
	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: " << file << ": offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void node::read_file(const std::string &remote, const std::string &file, uint64_t offset, uint64_t size, int type)
{
	int err;

	err = dnet_read_file(m_node, file.c_str(), remote.data(), remote.size(), offset, size, type);
	if (err) {
		struct dnet_id id;
		transform(remote, id);
		id.type = 0;

		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: " << file << ": offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void node::write_file(struct dnet_id &id, const std::string &file, uint64_t local_offset,
		uint64_t offset, uint64_t size, uint64_t cflags, unsigned int ioflags)
{
	int err = dnet_write_file_id(m_node, file.c_str(), &id, local_offset, offset, size, cflags, ioflags);
	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": WRITE: " << file << ", local_offset: " << local_offset <<
			", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}
void node::write_file(const std::string &remote, const std::string &file, uint64_t local_offset, uint64_t offset, uint64_t size,
		uint64_t cflags, unsigned int ioflags, int type)
{
	int err = dnet_write_file(m_node, file.c_str(), remote.data(), remote.size(),
			local_offset, offset, size, cflags, ioflags, type);
	if (err) {
		struct dnet_id id;
		transform(remote, id);
		id.type = 0;

		std::ostringstream str;
		str << dnet_dump_id(&id) << ": WRITE: " << file << ", local_offset: " << local_offset <<
			", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

std::string node::read_data_wait(struct dnet_id &id, uint64_t offset, uint64_t size,
		uint64_t cflags, uint32_t ioflags)
{
	struct dnet_io_attr io;
	int err;

	memset(&io, 0, sizeof(io));
	io.size = size;
	io.offset = offset;
	io.flags = ioflags;
	io.type = id.type;

	memcpy(io.id, id.id, DNET_ID_SIZE);
	memcpy(io.parent, id.id, DNET_ID_SIZE);

	void *data = dnet_read_data_wait(m_node, &id, &io, cflags, &err);
	if (!data) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: size: " << size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::string ret = std::string((const char *)data + sizeof(struct dnet_io_attr), io.size - sizeof(struct dnet_io_attr));
	free(data);

	return ret;
}

std::string node::read_data_wait(const std::string &remote, uint64_t offset, uint64_t size,
		uint64_t cflags, uint32_t ioflags, int type)
{
	struct dnet_id id;

	transform(remote, id);
	id.type = type;

	return read_data_wait(id, offset, size, cflags, ioflags);
}

void node::prepare_latest(struct dnet_id &id, uint64_t cflags, std::vector<int> &groups)
{
	struct dnet_read_latest_prepare pr;
	int err;

	memset(&pr, 0, sizeof(struct dnet_read_latest_prepare));

	pr.n = m_node;
	pr.id = id;
	pr.cflags = cflags;

	pr.group = (int *)malloc(groups.size() * sizeof(int));
	if (!pr.group) {
		std::ostringstream str;

		str << dnet_dump_id(&id) << ": prepare_latest: allocation failure: group num: " << groups.size();
		throw std::runtime_error(str.str());
	}
	pr.group_num = groups.size();

	for (unsigned i = 0; i < groups.size(); ++i)
		pr.group[i] = groups[i];

	err = dnet_read_latest_prepare(&pr);
	if (!err) {
		try {
			groups.clear();

			for (int i = 0; i < pr.group_num; ++i)
				groups.push_back(pr.group[i]);
		} catch (...) {
			free(pr.group);
			throw;
		}
	}

	free(pr.group);

	if (!groups.size())
		err = -ENOENT;

	if (err) {
		std::ostringstream str;

		str << dnet_dump_id(&id) << ": prepare_latest: groups: " << groups.size() << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}
}

std::string node::read_latest(struct dnet_id &id, uint64_t offset, uint64_t size,
		uint64_t cflags, uint32_t ioflags)
{
	struct dnet_io_attr io;
	void *data;
	int err;

	memset(&io, 0, sizeof(io));
	io.size = size;
	io.offset = offset;
	io.flags = ioflags;
	io.type = id.type;
	io.num = groups.size();

	memcpy(io.id, id.id, DNET_ID_SIZE);
	memcpy(io.parent, id.id, DNET_ID_SIZE);

	err = dnet_read_latest(m_node, &id, &io, cflags, &data);
	if (err < 0) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": READ: size: " << size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::string ret = std::string((const char *)data + sizeof(struct dnet_io_attr), io.size - sizeof(struct dnet_io_attr));
	free(data);

	return ret;
}

std::string node::read_latest(const std::string &remote, uint64_t offset, uint64_t size,
		uint64_t cflags, uint32_t ioflags, int type)
{
	struct dnet_id id;

	transform(remote, id);
	id.type = type;

	return read_latest(id, offset, size, cflags, ioflags);
}

std::string node::write_data_wait(struct dnet_id &id, const std::string &str,
		uint64_t remote_offset, uint64_t cflags, unsigned int ioflags)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = cflags;
	ctl.data = str.data();

	ctl.io.flags = ioflags;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = id.type;
	ctl.io.num = str.size() + remote_offset;

	memcpy(&ctl.id, &id, sizeof(struct dnet_id));

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_node, &ctl, (void **)&result);
	if (err < 0) {
		std::ostringstream string;
		string << dnet_dump_id(&id) << ": WRITE: size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}

	std::string ret((const char *)result, err);
	free(result);

	return ret;
}

std::string node::write_data_wait(const std::string &remote, const std::string &str,
		uint64_t remote_offset, uint64_t cflags, unsigned int ioflags, int type)
{
	struct dnet_id id;

	transform(remote, id);
	id.type = type;
	id.group_id = 0;

	return write_data_wait(id, str, remote_offset, cflags, ioflags);
}

std::string node::lookup_addr(const std::string &remote, const int group_id)
{
	char buf[128];

	int err = dnet_lookup_addr(m_node, remote.data(), remote.size(), NULL, group_id, buf, sizeof(buf));
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to lookup in group " << group_id << ": key size: " << remote.size() << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)buf, strlen(buf));
}

std::string node::lookup_addr(const struct dnet_id &id)
{
	char buf[128];

	int err = dnet_lookup_addr(m_node, NULL, 0, (struct dnet_id *)&id, id.group_id, buf, sizeof(buf));
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to lookup " << dnet_dump_id(&id) << ": err: " << err;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)buf, strlen(buf));
}

std::string node::create_metadata(const struct dnet_id &id, const std::string &obj,
		const std::vector<int> &groups, const struct timespec &ts)
{
	struct dnet_metadata_control ctl;
	struct dnet_meta_container mc;
	int err;

	memset(&mc, 0, sizeof(struct dnet_meta_container));
	memset(&ctl, 0, sizeof(struct dnet_metadata_control));

	ctl.obj = (char *)obj.data();
	ctl.len = obj.size();
	
	ctl.groups = (int *)&groups[0];
	ctl.group_num = groups.size();

	ctl.ts = ts;
	ctl.id = id;

	err = dnet_create_metadata(m_node, &ctl, &mc);
	if (err) {
		std::ostringstream str;
		str << "Failed to create metadata: key: " << dnet_dump_id(&id) << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	std::string ret;

	try {
		ret.assign((char *)mc.data, mc.size);
	} catch (...) {
		free(mc.data);
		throw;
	}

	free(mc.data);
	return ret;
}

int node::write_metadata(const struct dnet_id &id, const std::string &obj,
		const std::vector<int> &groups, const struct timespec &ts, uint64_t cflags)
{
	int err;
	std::string meta;
	struct dnet_meta_container mc;

	if (dnet_flags(m_node) & DNET_CFG_NO_META)
		return 0;

	meta = create_metadata(id, obj, groups, ts);

	mc.data = (void *)meta.data();
	mc.size = meta.size();

	mc.id = id;

	err = dnet_write_metadata(m_node, &mc, 1, cflags);
	if (err) {
		std::ostringstream str;
		str << "Failed to write metadata: key: " << dnet_dump_id(&id) << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	return 0;
}
		
void node::transform(const std::string &data, struct dnet_id &id)
{
	dnet_transform(m_node, (void *)data.data(), data.size(), &id);
}

void node::lookup(const struct dnet_id &id, const callback &c)
{
	int err = dnet_lookup_object(m_node, (struct dnet_id *)&id, 0,
			callback::complete_callback,
			(void *)&c);

	if (err) {
		std::ostringstream str;
		str << "Failed to lookup ID " << dnet_dump_id(&id) << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void node::lookup(const std::string &data, const callback &c)
{
	struct dnet_id id;
	int error = -ENOENT, i, num, *g;

	transform(data, id);
	id.type = 0;

	num = dnet_mix_states(m_node, &id, &g);
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

std::string node::lookup(const std::string &data)
{
	struct dnet_id id;
	int error = -ENOENT, i, num, *g;
	std::string ret;

	transform(data, id);
	id.type = 0;

	num = dnet_mix_states(m_node, &id, &g);
	if (num < 0)
		throw std::bad_alloc();

	for (i=0; i<num; ++i) {
		try {
			callback l;
			id.group_id = g[i];

			lookup(id, l);
			ret = l.wait();

			if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)) {
				std::stringstream str;

				str << dnet_dump_id(&id) << ": failed to receive lookup request";
				throw std::runtime_error(str.str());
			}
			/* reply parsing examaple */
#if 0
			struct dnet_addr *addr = (struct dnet_addr *)ret.data();
			struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);

			if (cmd->size > sizeof(struct dnet_addr_attr)) {
				struct dnet_addr_attr *a = (struct dnet_addr_attr *)(cmd + 1);
				struct dnet_file_info *info = (struct dnet_file_info *)(a + 1);

				dnet_convert_addr_attr(a);
				dnet_convert_file_info(info);
			}
#endif
			dnet_log_raw(m_node, DNET_LOG_DSA, "%s: %s: %zu bytes\n", dnet_dump_id(&id), data.c_str(), ret.size());
			error = 0;
			break;
		} catch (const std::exception &e) {
			dnet_log_raw(m_node, DNET_LOG_ERROR, "%s: %s : %s\n", dnet_dump_id(&id), e.what(), data.c_str());
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

std::string node::lookup(const struct dnet_id &id)
{
	int error = -ENOENT;
	std::string ret;

	try {
		callback l;

		lookup(id, l);
		ret = l.wait();

		if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd)) {
			std::stringstream str;

			str << dnet_dump_id(&id) << ": failed to receive lookup request";
			throw std::runtime_error(str.str());
		}

		dnet_log_raw(m_node, DNET_LOG_DSA, "%s: %zu bytes\n", dnet_dump_id(&id), ret.size());
		error = 0;
	} catch (const std::exception &e) {
		dnet_log_raw(m_node, DNET_LOG_ERROR, "%s: %s\n", dnet_dump_id(&id), e.what());
	}

	if (error) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": could not find object";

		throw std::runtime_error(str.str());
	}

	return ret;
}

void node::remove_raw(struct dnet_id &id, uint64_t cflags)
{
	int err = -ENOENT;
	std::vector<int> g = groups;

	for (int i=0; i<(int)g.size(); ++i) {
		id.group_id = g[i];

		if (!dnet_remove_object_now(m_node, &id, cflags))
			err = 0;
	}

	if (err) {
		std::ostringstream str;
		str << dnet_dump_id(&id) << ": REMOVE: " << err;
		throw std::runtime_error(str.str());
	}
}

void node::remove(struct dnet_id &id)
{
	remove_raw(id, 0);
}

void node::remove_raw(const std::string &data, int type, uint64_t cflags)
{
	struct dnet_id id;

	transform(data, id);
	id.type = type;

	remove_raw(id, cflags);
}

void node::remove(const std::string &data, int type)
{
	remove_raw(data, type, 0);
}

std::string node::stat_log()
{
	callback c;
	std::string ret;
	int err;

	err = dnet_request_stat(m_node, NULL, DNET_CMD_STAT, 0,
		callback::complete_callback, (void *)&c);
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to request statistics: " << err;
		throw std::runtime_error(str.str());
	}

	ret = c.wait(err);

	/* example reply parsing */
#if 0
	float la[3];
	const void *data = ret.data();
	int size = ret.size();
	char id_str[DNET_ID_SIZE*2 + 1];
	char addr_str[128];

	while (size) {
		struct dnet_addr *addr = (struct dnet_addr *)data;
		struct dnet_cmd *cmd = (struct dnet_cmd *)(addr + 1);
		struct dnet_stat *st = (struct dnet_stat *)(cmd + 1);

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

		int sz = sizeof(*addr) + sizeof(*cmd) + cmd->size;

		size -= sz;
		data += sz;
	}
#endif

	if (ret.size() < sizeof(struct dnet_addr) + sizeof(struct dnet_cmd) + sizeof(struct dnet_stat))
		throw std::runtime_error("Failed to request statistics: not enough data returned");
	return ret;
}

int node::state_num(void)
{
	return dnet_state_num(m_node);
}

int node::request_cmd(struct dnet_trans_control &ctl)
{
	int err;

	err = dnet_request_cmd(m_node, &ctl);
	if (err < 0) {
		std::ostringstream str;
		str << dnet_dump_id(&ctl.id) << ": failed to request cmd: " << dnet_cmd_string(ctl.cmd) << ": " << err;
		throw std::runtime_error(str.str());
	}

	return err;
}

void node::update_status(const char *saddr, const int port, const int family, struct dnet_node_status *status)
{
	int err;
	struct dnet_addr addr;
	char sport[16];

	memset(&addr, 0, sizeof(addr));
	addr.addr_len = sizeof(addr.addr);

	snprintf(sport, sizeof(sport), "%d", port);

	err = dnet_fill_addr(&addr, saddr, sport, family, SOCK_STREAM, IPPROTO_TCP);
	if (!err)
		err = dnet_update_status(m_node, &addr, NULL, status);

	if (err < 0) {
		std::ostringstream str;
		str << saddr << ":" << port << ": failed to request set status " << std::hex << status << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void node::update_status(struct dnet_id &id, struct dnet_node_status *status)
{
	int err;

	err = dnet_update_status(m_node, NULL, &id, status);
	if (err < 0) {
		std::ostringstream str;

		str << dnet_dump_id(&id) << ": failed to request set status " << std::hex << status << ": " << err;
		throw std::runtime_error(str.str());
	}
}

struct range_sort_compare {
		bool operator () (const std::string &s1, const std::string &s2) {
			unsigned char *id1 = (unsigned char *)s1.data();
			unsigned char *id2 = (unsigned char *)s2.data();

			int cmp = dnet_id_cmp_str(id1, id2);

			return cmp < 0;
		}
};

std::vector<std::string> node::read_data_range(struct dnet_io_attr &io, int group_id, uint64_t cflags)
{
	struct dnet_range_data *data;
	uint64_t num = 0;
	uint32_t ioflags = io.flags;
	int err;

	data = dnet_read_range(m_node, &io, group_id, cflags, &err);
	if (!data && err) {
		std::ostringstream str;
		str << "Failed to read range data object: group: " << group_id <<
			", key: " << dnet_dump_id_str(io.id) <<
			", size: " << io.size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::vector<std::string> ret;

	if (data) {
		for (int i = 0; i < err; ++i) {
			struct dnet_range_data *d = &data[i];
			char *data = (char *)d->data;

			if (!(ioflags & DNET_IO_FLAGS_NODATA)) {
				while (d->size) {
					struct dnet_io_attr *io = (struct dnet_io_attr *)data;

					dnet_convert_io_attr(io);

					uint64_t size = dnet_bswap64(io->size);

					std::string str;

					str.append((char *)io->id, DNET_ID_SIZE);
					str.append((char *)&size, 8);
					str.append((const char *)(io + 1), io->size);

					ret.push_back(str);

					data += sizeof(struct dnet_io_attr) + io->size;
					d->size -= sizeof(struct dnet_io_attr) + io->size;
				}
			} else {
				if (d->size != sizeof(struct dnet_io_attr)) {
					std::ostringstream str;
					str << "Incorrect data size: d->size = " << d->size <<
						"sizeof = " << sizeof(struct dnet_io_attr);
					throw std::runtime_error(str.str());
				}
				struct dnet_io_attr *rep = (struct dnet_io_attr *)data;
				num += rep->num;
			}

			free(d->data);
		}

		free(data);

		if (ioflags & DNET_IO_FLAGS_NODATA) {
			std::ostringstream str;
			str << num;
			ret.push_back(str.str());
		}
	}

	return ret;
}

std::vector<struct dnet_io_attr> node::remove_data_range(struct dnet_io_attr &io, int group_id, uint64_t cflags)
{
	struct dnet_io_attr *retp;
	int ret_num;
	int err;

	retp = dnet_remove_range(m_node, &io, group_id, cflags, &ret_num, &err);

	if (!retp && err) {
		std::ostringstream str;
		str << "Failed to read range data object: group: " << group_id <<
			", key: " << dnet_dump_id_str(io.id) <<
			", size: " << io.size << ": err: " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	std::vector<struct dnet_io_attr> ret;;

	if (retp) {
		for (int i = 0; i < ret_num; ++i) {
			ret.push_back(retp[i]);
		}

		free(retp);
	}

	return ret;
}

std::string node::write_prepare(const std::string &remote, const std::string &str, uint64_t remote_offset,
		uint64_t psize, uint64_t cflags, unsigned int ioflags, int type)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = cflags;
	ctl.data = str.data();

	ctl.io.flags = ioflags | DNET_IO_FLAGS_PREPARE | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = type;
	ctl.io.num = psize;

	transform(remote, ctl.id);
	ctl.id.type = type;
	ctl.id.group_id = 0;

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_node, &ctl, (void **)&result);
	if (err < 0) {
		std::ostringstream string;
		string << dnet_dump_id(&ctl.id) << ": " << remote << ": write_prepare: size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}

	std::string ret(result, err);
	free(result);

	return ret;
}

std::string node::write_commit(const std::string &remote, const std::string &str, uint64_t remote_offset, uint64_t csize,
		uint64_t cflags, unsigned int ioflags, int type)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = cflags;
	ctl.data = str.data();

	ctl.io.flags = ioflags | DNET_IO_FLAGS_COMMIT | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = type;
	ctl.io.num = csize;

	transform(remote, ctl.id);
	ctl.id.type = type;
	ctl.id.group_id = 0;

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_node, &ctl, (void **)&result);
	if (err < 0) {
		std::ostringstream string;
		string << dnet_dump_id(&ctl.id) << ": " << remote << ": write_commit: size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}

	std::string ret(result, err);
	free(result);

	return ret;
}

std::string node::write_plain(const std::string &remote, const std::string &str, uint64_t remote_offset,
		uint64_t cflags, unsigned int ioflags, int type)
{
	struct dnet_io_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.cflags = cflags;
	ctl.data = str.data();

	ctl.io.flags = ioflags | DNET_IO_FLAGS_PLAIN_WRITE;
	ctl.io.offset = remote_offset;
	ctl.io.size = str.size();
	ctl.io.type = type;

	transform(remote, ctl.id);
	ctl.id.type = type;
	ctl.id.group_id = 0;

	ctl.fd = -1;

	char *result = NULL;
	int err = dnet_write_data_wait(m_node, &ctl, (void **)&result);
	if (err < 0) {
		std::ostringstream string;
		string << dnet_dump_id(&ctl.id) << ": " << remote << ": write_plain: size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}

	std::string ret(result, err);
	free(result);

	return ret;
}

std::vector<std::pair<struct dnet_id, struct dnet_addr> > node::get_routes()
{
	std::vector<std::pair<struct dnet_id, struct dnet_addr> > res;
	struct dnet_id *ids = NULL;
	struct dnet_addr *addrs = NULL;

	int count = 0;

	count = dnet_get_routes(m_node, &ids, &addrs);

	if (count > 0) {
		for (int i = 0; i < count; ++i) {
			res.push_back(std::make_pair(ids[i], addrs[i]));
		}
	}

	if (ids)
		free(ids);

	if (addrs)
		free(addrs);

	return res;
}

std::string node::exec(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &binary)
{
	std::vector<char> vec(event.size() + data.size() + binary.size() + sizeof(struct sph));
	std::string ret_str;

	struct sph *e = (struct sph *)&vec[0];
	void *ret = NULL;
	int err;

	memset(e, 0, sizeof(struct sph));

	e->data_size = data.size();
	e->binary_size = binary.size();
	e->event_size = event.size();

	memcpy(e->data, event.data(), event.size());
	memcpy(e->data + event.size(), data.data(), data.size());
	memcpy(e->data + event.size() + data.size(), binary.data(), binary.size());

	err = dnet_send_cmd(m_node, id, e, &ret);
	if (err < 0) {
		std::ostringstream str;

		str << (id ? dnet_dump_id(id) : "no-id-given") << ": failed to exec: event: " << event <<
			", data-size: " << data.size() <<
			", binary-size: " << binary.size() <<
			": " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	if (ret && err) {
		try {
			ret_str.assign((char *)ret, err);
		} catch (...) {
			free(ret);
			throw;
		}
		free(ret);
	}

	return ret_str;
}

std::string node::push(struct dnet_id *id, const std::string &event, const std::string &data, const std::string &binary)
{
	std::vector<char> vec(event.size() + data.size() + binary.size() + sizeof(struct sph));
	std::string ret_str;

	struct sph *e = (struct sph *)&vec[0];
	void *ret = NULL;
	int err;

	memset(e, 0, sizeof(struct sph));

	e->data_size = data.size();
	e->binary_size = binary.size();
	e->event_size = event.size();

	memcpy(e->data, event.data(), event.size());
	memcpy(e->data + event.size(), data.data(), data.size());
	memcpy(e->data + event.size() + data.size(), binary.data(), binary.size());

	err = dnet_send_cmd_nolock(m_node, id, e, &ret);
	if (err < 0) {
		std::ostringstream str;

		str << (id ? dnet_dump_id(id) : "no-id-given") << ": failed to push: event: " << event <<
			", data-size: " << data.size() <<
			", binary-size: " << binary.size() <<
			": " << strerror(-err) << ": " << err;
		throw std::runtime_error(str.str());
	}

	if (ret && err) {
		try {
			ret_str.assign((char *)ret, err);
		} catch (...) {
			free(ret);
			throw;
		}
		free(ret);
	}

	return ret_str;
}

namespace {
	bool dnet_io_attr_compare(const struct dnet_io_attr &io1, const struct dnet_io_attr &io2) {
		int cmp;

		cmp = dnet_id_cmp_str(io1.id, io2.id);
		return cmp < 0;
	}
}

std::vector<std::string> node::bulk_read(const std::vector<struct dnet_io_attr> &ios, uint64_t cflags)
{
	struct dnet_range_data *data;
	int num, *g, err;

	num = dnet_mix_states(m_node, NULL, &g);
	if (num < 0)
		throw std::runtime_error("could not fetch groups: " + std::string(strerror(num)));

	std::vector<int> groups;
	try {
		groups.assign(g, g + num);
		free(g);
	} catch (...) {
		free(g);
		throw;
	}

	std::vector<struct dnet_io_attr> tmp_ios = ios;
	std::sort(tmp_ios.begin(), tmp_ios.end(), dnet_io_attr_compare);

	std::vector<std::string> ret;

	for (std::vector<int>::iterator group = groups.begin(); group != groups.end(); ++group) {
		if (!tmp_ios.size())
			break;

		data = dnet_bulk_read(m_node, (struct dnet_io_attr *)(&tmp_ios[0]), tmp_ios.size(), *group, cflags, &err);
		if (!data && err) {
			std::ostringstream str;
			str << "Failed to read bulk data: group: " << *group <<
				": err: " << strerror(-err) << ": " << err;
			throw std::runtime_error(str.str());
		}

		if (data) {
			for (int i = 0; i < err; ++i) {
				struct dnet_range_data *d = &data[i];
				char *data = (char *)d->data;

				while (d->size) {
					struct dnet_io_attr *io = (struct dnet_io_attr *)data;

					for (std::vector<struct dnet_io_attr>::iterator it = tmp_ios.begin(); it != tmp_ios.end(); ++it) {
						int cmp = dnet_id_cmp_str(it->id, io->id);

						if (cmp == 0) {
							tmp_ios.erase(it);
							break;
						}
					}

					dnet_convert_io_attr(io);

					uint64_t size = dnet_bswap64(io->size);

					std::string str;

					str.append((char *)io->id, DNET_ID_SIZE);
					str.append((char *)&size, 8);
					str.append((const char *)(io + 1), io->size);

					ret.push_back(str);

					data += sizeof(struct dnet_io_attr) + io->size;
					d->size -= sizeof(struct dnet_io_attr) + io->size;
				}

				free(d->data);
			}

			free(data);
		}
	}

	return ret;
}

std::vector<std::string> node::bulk_read(const std::vector<std::string> &keys, uint64_t cflags)
{
	std::vector<struct dnet_io_attr> ios;
	struct dnet_io_attr io;
	memset(&io, 0, sizeof(io));

	ios.reserve(keys.size());

	for (size_t i = 0; i < keys.size(); ++i) {
		struct dnet_id id;

		transform(keys[i], id);
		memcpy(io.id, id.id, sizeof(io.id));
		ios.push_back(io);
	}

	return bulk_read(ios, cflags);
}

std::string node::bulk_write(const std::vector<struct dnet_io_attr> &ios, const std::vector<std::string> &data, uint64_t cflags)
{
	std::vector<struct dnet_io_control> ctls;
	unsigned int i;
	int err;

	if (ios.size() != data.size()) {
		std::ostringstream string;
		string << "BULK_WRITE: ios doesn't meet data: io.size: " << ios.size() << ", data.size: " << data.size();
		throw std::runtime_error(string.str());
	}

	ctls.reserve(ios.size());

	for(i = 0; i < ios.size(); ++i) {
		struct dnet_io_control ctl;
		memset(&ctl, 0, sizeof(ctl));

		ctl.cflags = cflags;
		ctl.data = data[i].data();

		ctl.io = ios[i];

		dnet_setup_id(&ctl.id, 0, (unsigned char *)ios[i].id);
		ctl.id.type = ios[i].type;

		ctl.fd = -1;

		ctls.push_back(ctl);
	}

	struct dnet_range_data ret = dnet_bulk_write(m_node, &ctls[0], ctls.size(), &err);
	if (err < 0) {
		std::ostringstream string;
		string << "BULK_WRITE: size: " << ret.size << ", err: " << err;
		throw std::runtime_error(string.str());
	}

	std::string ret_str((const char *)ret.data, ret.size);
	free(ret.data);

	return ret_str;
}

