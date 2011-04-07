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

void elliptics_node::read_file(struct dnet_id &id, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, const_cast<char *>(dst_file), NULL, 0, &id, offset, size, 0);
	if (err) {
		std::ostringstream str;
		str << "Failed read file " << dst_file << ": offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::read_file(std::string &remote, char *dst_file, uint64_t offset, uint64_t size)
{
	int err;

	if (!size)
		size = ~0ULL;

	err = dnet_read_file(node, dst_file, (void *)remote.data(), remote.size(), NULL, offset, size, 0);
	if (err) {
		std::ostringstream str;
		str << "Failed read file " << dst_file << ", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
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
	if (err) {
		std::ostringstream str;
		str << "Failed read data key: " << dnet_dump_id(&id) << ", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::read_data(std::string &remote, uint64_t offset, uint64_t size, elliptics_callback &c)
{
	int err, error = 0, i;
	struct dnet_id id;

	dnet_transform(node, (void *)remote.data(), remote.size(), &id);
	for (i=0; i<groups.size(); ++i) {
		id.group_id = groups[i];

		try {
			read_data(id, offset, size, c);
		} catch (...) {
			error++;
			continue;
		}

		error = 0;
		break;
	}

	if (error) {
		std::ostringstream str;
		str << "Failed read data key: " << dnet_dump_id(&id) << ", offset: " << offset << ", size: " << size;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::write_file(struct dnet_id &id, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, NULL, 0, &id, local_offset, offset, size, aflags, ioflags);
	if (err) {
		std::ostringstream str;
		str << "Failed write file " << src_file << ", local_offset: " << local_offset << ", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
}
void elliptics_node::write_file(std::string &remote, char *src_file, uint64_t local_offset, uint64_t offset, uint64_t size,
		unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_file_local_offset(node, src_file, (void *)remote.data(), remote.size(), NULL, local_offset, offset, size, aflags, ioflags);
	if (err) {
		std::ostringstream str;
		str << "Failed write file " << src_file << ", local_offset: " << local_offset << ", offset: " << offset << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}
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
	if (err == 0)
		err = -ENOENT;
	if (err < 0) {
		std::ostringstream str;
		str << "Failed write data: key: " << dnet_dump_id(id) << ", size: " << size << ": " << err;
		throw std::runtime_error(str.str());
	}

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
	if (!data) {
		std::ostringstream str;
		str << "Failed read single data object: key: " << dnet_dump_id(&id) << ", size: " << size;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)data, size);
}

std::string elliptics_node::read_data_wait(std::string &remote, uint64_t size)
{
	struct dnet_id id;
	int err, error = 0, i;
	std::string ret;

	dnet_transform(node, (void *)remote.data(), remote.size(), &id);
	for (i=0; i<groups.size(); ++i) {
		id.group_id = groups[i];

		try {
			ret = read_data_wait(id, size);
		} catch (...) {
			error++;
			continue;
		}

		error = 0;
		break;
	}

	if (error) {
		std::ostringstream str;
		str << "Failed read data object: key: " << dnet_dump_id(&id) << ", size: " << size;
		throw std::runtime_error(str.str());
	}

	return ret;
}

int elliptics_node::write_data_wait(struct dnet_id &id, std::string &str, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, NULL, 0, &id, (void *)str.data(), -1, 0, 0, str.size(), NULL, aflags, ioflags);
	if (err < 0) {
		std::ostringstream string;
		string << "Failed write data object: key: " << dnet_dump_id(&id) << ", size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}
	return err;
}

int elliptics_node::write_data_wait(std::string &remote, std::string &str, unsigned int aflags, unsigned int ioflags)
{
	int err = dnet_write_data_wait(node, (void *)remote.data(), remote.size(), NULL, (void *)str.data(), -1, 0, 0, str.size(), NULL, aflags, ioflags);
	if (err < 0) {
		std::ostringstream string;
		string << "Failed write data object: key size: " << remote.size() << ", size: " << str.size() << ", err: " << err;
		throw std::runtime_error(string.str());
	}
	return err;
}

std::string elliptics_node::lookup_addr(const std::string &remote, const int group_id)
{
	char buf[128];

	int err = dnet_lookup_addr(node, (void *)remote.data(), remote.size(), group_id, buf, sizeof(buf));
	if (err < 0) {
		std::ostringstream str;
		str << "Failed to lookup in group " << group_id << ": key size: " << remote.size() << ", err: " << err;
		throw std::runtime_error(str.str());
	}

	return std::string((const char *)buf, strlen(buf));
}

int elliptics_node::write_metadata(const struct dnet_id &id, const std::string &obj, const std::vector<int> &groups)
{
	int err;

	err = dnet_create_write_metadata(node, (struct dnet_id *)&id, (char *)obj.data(), obj.size(), (int *)&groups[0], groups.size());
	if (err < 0) {
		std::ostringstream str;
		str << "Failed write metadata: key: " << dnet_dump_id(&id) << ", err: " << err;
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
	int err = dnet_lookup_object(node, (struct dnet_id *)&id, DNET_ATTR_LOOKUP_STAT,
			elliptics_callback::elliptics_complete_callback,
			(void *)&c);

	if (err) {
		std::ostringstream str;
		str << "Failed lookup ID " << dnet_dump_id(&id) << ": " << err;
		throw std::runtime_error(str.str());
	}
}

void elliptics_node::lookup(const std::string &data, const elliptics_callback &c)
{
	struct dnet_id id;
	int error = -ENOENT, ret, i;

	transform(data, id);

	for (i=0; i<groups.size(); ++i) {
		id.group_id = groups[i];

		try {
			lookup(id, c);
		} catch (...) {
			continue;
		}

		error = 0;
		break;
	}

	if (error) {
		std::ostringstream str;
		str << "Failed lookup data object: key: " << dnet_dump_id(&id);
		throw std::runtime_error(str.str());
	}
}

class elliptics_lookup_callback : public elliptics_callback {
	public:
		elliptics_lookup_callback() : wait(PTHREAD_COND_INITIALIZER), lock(PTHREAD_MUTEX_INITIALIZER), complete(0) {};

		std::string data;
		pthread_cond_t wait;
		pthread_mutex_t lock;
		int complete;

		int callback(void) {
			if (is_trans_destroyed(state, cmd, attr)) {
				pthread_mutex_lock(&lock);
				complete = 1;
				pthread_cond_broadcast(&wait);
				pthread_mutex_unlock(&lock);
			} else if (cmd && state && attr && cmd->size) {
				struct dnet_addr_attr *a = (struct dnet_addr_attr *)(attr + 1);
				struct dnet_node *n = dnet_get_node_from_state(state);

				dnet_lookup_complete(state, cmd, attr, NULL);

				dnet_convert_addr_attr(a);

				dnet_log_raw(n, DNET_LOG_INFO, "%s: addr: %s, is object presented there: %d.\n",
						dnet_dump_id(&cmd->id),
						dnet_server_convert_dnet_addr(&a->addr),
						attr->flags);

				data.assign((const char*)a, attr->size);
			}
		};
};

std::string elliptics_node::lookup(const std::string &data)
{
	elliptics_lookup_callback *l = new elliptics_lookup_callback();

	try {
		lookup(data, *l);
		pthread_mutex_lock(&l->lock);
		while (!l->complete)
			pthread_cond_wait(&l->wait, &l->lock);
		pthread_mutex_unlock(&l->lock);
	} catch (...) {
		delete l;
		throw;
	}

	std::string ret(l->data);
	delete l;

	return ret;
}
