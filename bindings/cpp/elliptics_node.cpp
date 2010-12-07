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

#include "elliptics/cppdef.h"

elliptics_node::elliptics_node(elliptics_log &l)
{
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60;
	cfg.check_timeout = 60;

	log = reinterpret_cast<elliptics_log *>(l.clone());
	cfg.log = log->get_dnet_log();

	snprintf(cfg.addr, sizeof(cfg.addr), "0.0.0.0");
	snprintf(cfg.port, sizeof(cfg.port), "0");

	node = dnet_node_create(&cfg);
	if (!node) {
		delete log;
		throw;
	}
}

elliptics_node::~elliptics_node()
{
	dnet_node_destroy(node);
	delete log;
}

void elliptics_node::add_groups(int g[], int gnum)
{
	groups = new int [gnum];
	group_num = gnum;
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
	if (err)
		throw err;
}

void elliptics_node::read_file(struct dnet_id &id, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, const_cast<char *>(dst_file), NULL, 0, &id, offset, size, 0);
	if (err)
		throw err;
}

void elliptics_node::read_file(std::string &remote, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, dst_file, (void *)remote.data(), remote.size(), NULL, offset, size, 0);
	if (err)
		throw err;
}

void elliptics_node::read_data(struct dnet_id &id, uint64_t offset, uint64_t size, elliptics_callback &c)
{
	struct dnet_io_control ctl;
	int err;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;
	ctl.priv = reinterpret_cast<void *>(&c);
	ctl.complete = elliptics_callback::elliptics_complete_callback;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	memcpy(ctl.io.id, id.id, DNET_ID_SIZE);
	memcpy(ctl.io.parent, id.id, DNET_ID_SIZE);

	memcpy(&ctl.id, &id, sizeof(struct dnet_id));

	ctl.io.size = size;
	ctl.io.offset = offset;

	err = dnet_read_object(node, &ctl);
	if (err)
		throw err;
}

void elliptics_node::read_data(std::string &remote, uint64_t offset, uint64_t size, elliptics_callback &c)
{
	int err, error = 0, i;
	struct dnet_id id;

	dnet_transform(node, (void *)remote.data(), remote.size(), &id);
	for (i=0; i<group_num; ++i) {
		id.group_id = groups[i];

		try {
			read_data(id, offset, size, c);
		} catch (int err) {
			error = err;
		}

		error = 0;
		break;
	}

	if (error)
		throw error;
}

void elliptics_node::write_file(struct dnet_id &id, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, NULL, 0, &id, local_offset, offset, size, aflags, ioflags);
	if (err)
		throw err;
}
void elliptics_node::write_file(std::string &remote, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, (void *)remote.data(), remote.size(), NULL, local_offset, offset, size, aflags, ioflags);
	if (err)
		throw err;
}

int elliptics_node::write_data_ll(struct dnet_id *id, void *remote, unsigned int remote_len,
		void *data, unsigned int size, elliptics_callback &c,
		unsigned int aflags, unsigned int ioflags)
{
	struct dnet_io_control ctl;
	int trans_num = 0;
	int err;

	memset(&ctl, 0, sizeof(ctl));

	ctl.fd = -1;
	ctl.data = data;
	ctl.complete = elliptics_callback::elliptics_complete_callback;
	ctl.priv = reinterpret_cast<void *>(&c);

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = ioflags;
	ctl.io.size = size;

	err = dnet_write_object(node, &ctl, remote, remote_len, id,
		!(ioflags & (DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_META | DNET_IO_FLAGS_NO_HISTORY_UPDATE)));
	if (err < 0)
		throw err;
	if (err == 0)
		throw -ENOENT;

	return err;
}

int elliptics_node::write_data(struct dnet_id &id, std::string &str,
		elliptics_callback &c, unsigned int aflags, unsigned int ioflags)
{
	return write_data_ll(&id, NULL, 0, (void *)str.data(), str.size(), c, aflags, ioflags);
}

int elliptics_node::write_data(std::string &remote, std::string &str,
		elliptics_callback &c, unsigned int aflags, unsigned int ioflags)
{
	return write_data_ll(NULL, (void *)remote.data(), remote.size(), (void *)str.data(), str.size(), c, aflags, ioflags);
}

std::string elliptics_node::read_data_wait(struct dnet_id &id, uint64_t size)
{
	void *data = dnet_read_data_wait(node, &id, &size);
	if (!data)
		throw -1;

	return std::string((const char *)data, size);
}

std::string elliptics_node::read_data_wait(std::string &remote, uint64_t size)
{
	struct dnet_id id;
	int err, error = 0, i;
	std::string ret;

	dnet_transform(node, (void *)remote.data(), remote.size(), &id);
	for (i=0; i<group_num; ++i) {
		id.group_id = groups[i];

		try {
			ret = read_data_wait(id, size);
		} catch (int err) {
			error = err;
		}

		error = 0;
		break;
	}

	if (error < 0)
		throw error;

	return ret;

}

int elliptics_node::write_data_wait(struct dnet_id &id, std::string &str, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, NULL, 0, &id, (void *)str.data(), -1, 0, 0, str.size(), NULL, aflags, ioflags);
	if (err < 0)
		throw err;
	return err;
}

int elliptics_node::write_data_wait(std::string &remote, std::string &str, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, (void *)remote.data(), remote.size(), NULL, (void *)str.data(), -1, 0, 0, str.size(), NULL, aflags, ioflags);
	if (err < 0)
		throw err;
	return err;
}
