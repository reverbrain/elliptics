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

elliptics_node::elliptics_node(unsigned char *id, elliptics_log &l)
{
	struct dnet_config cfg;

	memset(&cfg, 0, sizeof(cfg));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60;
	cfg.check_timeout = 60;

	log = reinterpret_cast<elliptics_log *>(l.clone());
	cfg.log = log->get_dnet_log();

	memcpy(cfg.id, id, DNET_ID_SIZE);

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

static int elliptics_do_transform(void *priv, void *src, uint64_t size,
					   void *dst, unsigned int *dsize,
					   unsigned int flags)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	return t->transform(priv, src, size, dst, dsize, flags);
}

static void elliptics_do_transform_cleanup(void *priv)
{
	elliptics_transform *t = reinterpret_cast<elliptics_transform *>(priv);
	t->cleanup(priv);
}

void elliptics_node::add_transform(elliptics_transform &t)
{
	int err;
	err = dnet_add_transform(node, reinterpret_cast<void *>(&t), const_cast<char *>(t.get_name()),
			elliptics_do_transform, elliptics_do_transform_cleanup);
	if (err)
		throw err;
}

void elliptics_node::read_file(unsigned char *id, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, const_cast<char *>(dst_file), NULL, 0, id, offset, size, 0);
	if (err)
		throw err;
}

void elliptics_node::read_file(void *remote, unsigned int remote_size, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, dst_file, reinterpret_cast<char *>(remote), remote_size, NULL, offset, size, 0);
	if (err)
		throw err;
}

void elliptics_node::read_data(unsigned char *id, uint64_t offset, uint64_t size, elliptics_callback &c)
{
	struct dnet_io_control ctl;
	int err;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.fd = -1;
	ctl.priv = reinterpret_cast<void *>(&c);
	ctl.complete = elliptics_callback::elliptics_complete_callback;
	ctl.cmd = DNET_CMD_READ;
	ctl.cflags = DNET_FLAGS_NEED_ACK;

	memcpy(ctl.io.id, id, DNET_ID_SIZE);
	memcpy(ctl.io.origin, id, DNET_ID_SIZE);
	memcpy(ctl.addr, id, DNET_ID_SIZE);

	ctl.io.size = size;
	ctl.io.offset = offset;

	err = dnet_read_object(node, &ctl);
	if (err)
		throw err;
}

void elliptics_node::read_data(void *remote, unsigned int remote_size, uint64_t offset, uint64_t size, elliptics_callback &c)
{
	unsigned char id[DNET_ID_SIZE];
	int err, error = -ENOENT;
	int pos = 0;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(node, remote, remote_size, id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		try {
			read_data(id, offset, size, c);
		} catch (int) {
			error = err;
			/* ignore */
		}

		error = 0;
		break;
	}

	if (error)
		throw error;
}

void elliptics_node::write_file(unsigned char *id, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, NULL, 0, id, local_offset, offset, size, aflags, ioflags);
	if (err)
		throw err;
}
void elliptics_node::write_file(void *remote, unsigned int remote_size, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, remote, remote_size, NULL, local_offset, offset, size, aflags, ioflags);
	if (err)
		throw err;
}

int elliptics_node::write_data_ll(unsigned char *id, void *remote, unsigned int remote_len,
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

	err = dnet_write_object(node, &ctl, remote, remote_len, id, !(ioflags & DNET_IO_FLAGS_HISTORY), &trans_num);
	if (err)
		throw err;

	return trans_num;
}

int elliptics_node::write_data(unsigned char *id, void *data, unsigned int size,
		elliptics_callback &c, unsigned int aflags, unsigned int ioflags)
{
	return write_data_ll(id, NULL, 0, data, size, c, aflags, ioflags);
}

int elliptics_node::write_data(void *remote, unsigned int remote_len, void *data, unsigned int size,
		elliptics_callback &c, unsigned int aflags, unsigned int ioflags)
{
	return write_data_ll(NULL, remote, remote_len, data, size, c, aflags, ioflags);
}

void elliptics_node::read_data_wait(unsigned char *id, void *data, uint64_t offset, uint64_t size)
{
	int err = dnet_read_data_wait(node, id, data, offset, size);
	if (err)
		throw err;
}

void elliptics_node::read_data_wait(void *remote, unsigned int remote_size, void *data, uint64_t offset, uint64_t size)
{
	unsigned char id[DNET_ID_SIZE];
	int pos = 0;
	int err, error = 0;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(node, remote, remote_size, id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		try {
			read_data_wait(id, data, offset, size);
		} catch (int) {
			error = err;
			/* ignore */
		}

		error = 0;
		break;
	}

	if (error)
		throw error;
}

int elliptics_node::write_data_wait(unsigned char *id, void *data, uint64_t offset, uint64_t size, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, NULL, 0, id, data, offset, size, aflags, ioflags);
	if (err < 0)
		throw err;
	return err;
}

int elliptics_node::write_data_wait(void *remote, unsigned int remote_size, void *data, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, remote, remote_size, NULL, data, offset, size, aflags, ioflags);
	if (err < 0)
		throw err;
	return err;
}
