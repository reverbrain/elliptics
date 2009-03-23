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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "trans.h"
#include "elliptics.h"

#include "dnet/packet.h"
#include "dnet/interface.h"

static int dnet_transform(struct dnet_node *n, void *src, uint64_t size, void *dst, unsigned int *dsize, int *ppos)
{
	int pos = 0;
	int err = 1;
	struct dnet_transform *t;

	pthread_mutex_lock(&n->tlock);
	list_for_each_entry(t, &n->tlist, tentry) {
		if (pos++ == *ppos) {
			*ppos = pos;
			err = t->init(t->priv);
			if (err)
				continue;

			err = t->update(t->priv, src, size, dst, dsize, 0);
			if (err)
				continue;
			
			err = t->final(t->priv, dst, dsize, 0);
			if (!err)
				break;
		}
	}
	pthread_mutex_unlock(&n->tlock);

	return err;
}

static int dnet_cmd_lookup(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
{
	struct dnet_node *n = orig->n;
	struct dnet_net_state *st;
	struct dnet_addr_cmd l;
	int err;

	memset(&l, 0, sizeof(struct dnet_addr_cmd));

	st = dnet_state_search(n, cmd->id, NULL);
	if (!st)
		st = dnet_state_get(orig->n->st);

	memcpy(&l.cmd.id, st->id, DNET_ID_SIZE);
	l.cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);
	l.cmd.trans = cmd->trans | DNET_TRANS_REPLY;

	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		l.cmd.flags = DNET_FLAGS_MORE;

	memcpy(&l.addr.addr, &st->addr, sizeof(struct dnet_addr));
	l.addr.proto = n->proto;
	l.addr.sock_type = n->sock_type;

	dnet_state_put(st);

	l.a.cmd = DNET_CMD_LOOKUP;
	l.a.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);

	dnet_convert_addr_cmd(&l);

	pthread_mutex_lock(&orig->lock);
	err = dnet_send(orig, &l, sizeof(struct dnet_addr_cmd));
	pthread_mutex_unlock(&orig->lock);

	return err;
}

static int dnet_cmd_reverse_lookup(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data __unused)
{
	struct dnet_node *n = st->n;
	struct dnet_addr_cmd a;
	int err;

	memset(&a, 0, sizeof(struct dnet_addr_cmd));

	memcpy(&a.cmd.id, n->id, DNET_ID_SIZE);
	a.cmd.trans = cmd->trans | DNET_TRANS_REPLY;
	a.cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);

	if (cmd->flags & DNET_FLAGS_NEED_ACK)
		a.cmd.flags = DNET_FLAGS_MORE;

	a.a.cmd = DNET_CMD_REVERSE_LOOKUP;
	a.a.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);

	memcpy(&a.addr.addr, &n->addr, sizeof(struct dnet_addr));
	a.addr.proto = n->proto;
	a.addr.sock_type = n->sock_type;

	dnet_convert_addr_cmd(&a);

	pthread_mutex_lock(&st->lock);
	err = dnet_send(st, &a, sizeof(struct dnet_addr_cmd));
	pthread_mutex_unlock(&st->lock);

	return err;
}

static int dnet_cmd_join_client(struct dnet_net_state *orig, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *data)
{
	int err, s;
	struct dnet_net_state *st = NULL;
	struct dnet_node *n = orig->n;
	struct dnet_addr_attr *a = data;

	dnet_convert_addr_attr(a);

	s = dnet_socket_create_addr(n, a->sock_type, a->proto,
			(struct sockaddr *)&a->addr, a->addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	st = dnet_state_create(n, cmd->id, &a->addr, s, dnet_state_process);
	if (!st) {
		err = -EINVAL;
		goto err_out_close;
	}

	dnet_log(n, DNET_LOG_INFO, "%s: state %s.\n", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

err_out_close:
	close(s);
err_out_exit:
	dnet_log(n, DNET_LOG_ERROR, "%s: state %s -> ", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));
	if (st)
		dnet_log_append(n, DNET_LOG_ERROR, "%s, .\n", dnet_dump_id(st->id));
	dnet_log_append(n, DNET_LOG_ERROR, "err: %d.\n", err);
	return err;
}

static int dnet_update_history(struct dnet_node *n, unsigned char *id, struct dnet_io_attr *io, int tmp)
{
	char history[DNET_ID_SIZE*2+1 + sizeof(DNET_HISTORY_SUFFIX) + 5 + 3]; /* ff/$IDDNET_HISTORY_SUFFIX.tmp*/
	int fd, err;

	snprintf(history, sizeof(history), "%02x/%s%s%s", id[0], dnet_dump_id(id), DNET_HISTORY_SUFFIX, (tmp)?".tmp":"");

	fd = open(history, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open history file '%s'", dnet_dump_id(id), history);
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);
	err = write(fd, io, sizeof(struct dnet_io_attr));
	dnet_convert_io_attr(io);

	if (err <= 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to update history file '%s'", dnet_dump_id(id), history);
		goto err_out_close;
	}

	fsync(fd);
	close(fd);
	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_cmd_write(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err;
	struct dnet_node *n = st->n;
	char dir[3];
	struct dnet_io_attr *io = data;
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE;
	char file[DNET_ID_SIZE * 2 + 1 + 3]; /* null byte + '%02x/' directory prefix */

	if (!n->root) {
		dnet_log(n, DNET_LOG_ERROR, "%s: can not write without root dir.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (attr->size <= sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	snprintf(dir, sizeof(dir), "%02x", cmd->id[0]);

	err = mkdir(dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_log_err(n, "%s: faliled to create dir '%s' in the root '%s'",
					dnet_dump_id(cmd->id), dir, n->root);
			goto err_out_exit;
		}
	}

	snprintf(file, sizeof(file), "%02x/%s", cmd->id[0], dnet_dump_id(cmd->id));

	if (!(io->flags & DNET_IO_FLAGS_UPDATE)) {
		int fd;

		if ((io->size != attr->size - sizeof(struct dnet_io_attr)) ||
				(io->size > cmd->size)){
			dnet_log(n, DNET_LOG_ERROR, "%s: wrong io size: %llu, must be equal to %llu.\n",
					dnet_dump_id(cmd->id), (unsigned long long)io->size,
					(unsigned long long)attr->size - sizeof(struct dnet_io_attr));
			err = -EINVAL;
			goto err_out_exit;
		}

		if (io->flags & DNET_IO_FLAGS_APPEND)
			oflags |= O_APPEND;

		fd = open(file, oflags, 0644);
		if (fd < 0) {
			err = -errno;
			dnet_log_err(n, "%s: failed to open data file '%s/%s'",
					dnet_dump_id(cmd->id), n->root, file);
			goto err_out_exit;
		}

		err = pwrite(fd, data, io->size, io->offset);
		if (err <= 0) {
			err = -errno;
			dnet_log_err(n, "%s: failed to write into '%s/%s'",
				dnet_dump_id(cmd->id), n->root, file);
			close(fd);
			goto err_out_exit;
		}

		fsync(fd);
		close(fd);
	}

	err = dnet_update_history(n, cmd->id, io, 0);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to update history for '%s/%s'",
			dnet_dump_id(cmd->id), n->root, file);
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "%s: IO file: '%s/%s', offset: %llu, size: %llu.\n",
			dnet_dump_id(cmd->id), n->root, file,
			(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_exit:
	return err;
}

static int dnet_cmd_read(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_io_attr *io = data;
	char file[DNET_ID_SIZE * 2 + 1 + 3 + sizeof(DNET_HISTORY_SUFFIX)]; /* null byte + '%02x/' directory prefix + history suffix */
	int dd, err;
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_io_attr *rio;
	size_t size;
	off_t offset;
	uint64_t total_size;

	if (attr->size != sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);

	if (attr->flags)
		snprintf(file, sizeof(file), "%02x/%s%s", io->id[0], dnet_dump_id(io->id), DNET_HISTORY_SUFFIX);
	else
		snprintf(file, sizeof(file), "%02x/%s", io->id[0], dnet_dump_id(io->id));

	dd = open(file, O_RDONLY, 0644);
	if (dd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open data file '%s/%s'",
				dnet_dump_id(io->id), n->root, file);
		goto err_out_exit;
	}

	size = io->size;
	if (io->size == 0) {
		struct stat st;

		err = fstat(dd, &st);
		if (err) {
			err = -errno;
			dnet_log_err(n, "%s: failed to stat file '%s/%s'", dnet_dump_id(io->id), n->root, file);
			goto err_out_close_dd;
		}

		size = st.st_size;
	}

	c = malloc(sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
	if (!c) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate reply attributes.\n", dnet_dump_id(io->id));
		goto err_out_close_dd;
	}

	total_size = size;
	offset = io->offset;

	while (total_size) {
		size = total_size;
		if (size > DNET_MAX_READ_TRANS_SIZE)
			size = DNET_MAX_READ_TRANS_SIZE;

		dnet_log(n, DNET_LOG_NOTICE, "%s: offset: %llu, size: %zu, c: %p.\n", dnet_dump_id(io->id),
				(unsigned long long)io->offset, size, c);

		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->id, DNET_ID_SIZE);

		if (total_size <= DNET_MAX_READ_TRANS_SIZE) {
			if (cmd->flags & DNET_FLAGS_NEED_ACK)
				c->flags = DNET_FLAGS_MORE;
		} else
			c->flags = DNET_FLAGS_MORE;

		c->status = 0;
		c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
		c->trans = cmd->trans | DNET_TRANS_REPLY;

		a->cmd = DNET_CMD_READ;
		a->size = sizeof(struct dnet_io_attr) + size;
		a->flags = attr->flags;

		memcpy(rio->id, io->id, DNET_ID_SIZE);
		rio->size = size;
		rio->offset = offset;
		rio->flags = 0;

		dnet_convert_cmd(c);
		dnet_convert_attr(a);
		dnet_convert_io_attr(rio);

		err = dnet_sendfile_data(st, dd, offset, size,
			c, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to send read reply.\n", dnet_dump_id(io->id));
			goto err_out_free;
		}

		offset += size;
		total_size -= size;
	}

	free(c);
	close(dd);

	return 0;

err_out_free:
	free(c);
err_out_close_dd:
	close(dd);
err_out_exit:
	return err;
}

static int dnet_cmd_exec(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	char *command = data;
	struct dnet_node *n = st->n;
	pid_t pid;
	int err;

	if (!attr->size)
		return 0;

	dnet_log(n, DNET_LOG_NOTICE, "%s: command: '%s'.\n", dnet_dump_id(cmd->id), command);

	pid = fork();
	if (pid < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to fork a child process", dnet_dump_id(cmd->id));
		goto out_exit;
	}

	if (pid == 0) {
		err = system(command);
		exit(err);
	} else {
		int status;

		err = waitpid(pid, &status, 0);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "%s: failed to wait for child (%d) process", dnet_dump_id(cmd->id), (int)pid);
			goto out_exit;
		}

		if (WIFEXITED(status))
			err = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			err = -EPIPE;
	}

out_exit:
	return err;
}

int dnet_process_cmd(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data)
{
	int err = 0;
	unsigned long long size = cmd->size;
	struct dnet_node *n = st->n;

	while (size) {
		struct dnet_attr *a = data;
		unsigned long long sz;

		dnet_convert_attr(a);
		sz = a->size;

		if (size < sizeof(struct dnet_attr)) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: 1 wrong cmd: size: %llu/%llu, attr_size: %llu.\n",
					dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EPROTO;
			break;
		}

		data += sizeof(struct dnet_attr);
		size -= sizeof(struct dnet_attr);
		
		if (size < a->size) {
			dnet_log(n, DNET_LOG_ERROR, "%s: 2 wrong cmd: size: %llu/%llu, attr_size: %llu.\n",
				dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EPROTO;
			break;
		}

		dnet_log(n, DNET_LOG_NOTICE, "%s: trans: %llu, size_left: %llu, starting cmd: %u, asize: %llu.\n",
			dnet_dump_id(cmd->id), (unsigned long long)cmd->trans,
			size, a->cmd, (unsigned long long)a->size);

		switch (a->cmd) {
			case DNET_CMD_LOOKUP:
				err = dnet_cmd_lookup(st, cmd, a, data);
				break;
			case DNET_CMD_REVERSE_LOOKUP:
				err = dnet_cmd_reverse_lookup(st, cmd, a, data);
				break;
			case DNET_CMD_JOIN:
				err = dnet_cmd_join_client(st, cmd, a, data);
				break;
			case DNET_CMD_WRITE:
				err = dnet_cmd_write(st, cmd, a, data);
				break;
			case DNET_CMD_READ:
				err = dnet_cmd_read(st, cmd, a, data);
				break;
			case DNET_CMD_LIST:
				err = dnet_cmd_list(st, cmd);
				break;
			case DNET_CMD_EXEC:
				err = dnet_cmd_exec(st, cmd, a, data);
				break;
			default:
				err = -EPROTO;
				break;
		}

		dnet_log(n, DNET_LOG_INFO, "%s: trans: %llu, size_left: %llu, completed cmd: %u, asize: %llu, err: %d.\n",
			dnet_dump_id(cmd->id), (unsigned long long)cmd->trans, size,
			a->cmd, (unsigned long long)a->size, err);

		if (err)
			break;

		if (size < sz) {
			dnet_log(n, DNET_LOG_ERROR, "%s: 3 wrong cmd: size: %llu/%llu, attr_size: %llu.\n",
				dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EPROTO;
			break;
		}

		data += sz;
		size -= sz;
	}

	if (cmd->flags & DNET_FLAGS_NEED_ACK) {
		struct dnet_cmd ack;

		memcpy(ack.id, cmd->id, DNET_ID_SIZE);
		ack.trans = cmd->trans | DNET_TRANS_REPLY;
		ack.size = 0;
		ack.flags = cmd->flags & ~DNET_FLAGS_NEED_ACK;
		ack.status = err;

		dnet_log(n, DNET_LOG_NOTICE, "%s: ack trans: %llu, flags: %x, status: %d.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->trans, ack.flags, err);

		dnet_convert_cmd(&ack);

		pthread_mutex_lock(&st->lock);
		dnet_send(st, &ack, sizeof(struct dnet_cmd));
		pthread_mutex_unlock(&st->lock);
	}

	return err;
}

int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg)
{
	int s, err;
	struct dnet_net_state *st, dummy;
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_attr)];
	struct dnet_addr addr;
	struct dnet_addr_cmd acmd;
	struct dnet_cmd *cmd;
	struct dnet_attr *a;

	addr.addr_len = sizeof(addr.addr);
	s = dnet_socket_create(n, cfg, (struct sockaddr *)&addr.addr, &addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	memset(buf, 0, sizeof(buf));

	cmd = (struct dnet_cmd *)(buf);
	a = (struct dnet_attr *)(cmd + 1);

	cmd->size = sizeof(struct dnet_attr);
	a->cmd = DNET_CMD_REVERSE_LOOKUP;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	st = &dummy;
	memset(st, 0, sizeof(struct dnet_net_state));

	st->s = s;
	st->n = n;
	st->timeout = n->wait_ts.tv_sec * 1000;

	err = dnet_send(st, buf, sizeof(buf));
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to send reverse lookup message to %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	err = dnet_recv(st, &acmd, sizeof(acmd));
	if (err < 0) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to receive reverse lookup response from %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	dnet_convert_addr_cmd(&acmd);

	dnet_log(n, DNET_LOG_NOTICE, "%s: reverse lookup: ", dnet_dump_id(n->id));
	dnet_log_append(n, DNET_LOG_NOTICE, "%s -> %s.\n", dnet_dump_id(acmd.cmd.id),
		dnet_server_convert_dnet_addr(&acmd.addr.addr));

	st = dnet_state_create(n, acmd.cmd.id, &acmd.addr.addr, s, dnet_state_process);
	if (!st) {
		err = -EINVAL;
		goto err_out_sock_close;
	}

	return 0;

err_out_sock_close:
	close(s);
err_out_exit:
	return err;
}

int dnet_rejoin(struct dnet_node *n, int all)
{
	struct dnet_addr_cmd a;
	int err = 0;
	struct dnet_net_state *st;

	if (!n->root) {
		dnet_log(n, DNET_LOG_ERROR, "%s: can not join without root directory to store data.\n", dnet_dump_id(n->id));
		return -EINVAL;
	}

	/*
	 * Need to sync local content.
	 */
	err = dnet_recv_list(n, NULL);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "%s: content sync failed, error: %d.\n", dnet_dump_id(n->id), err);
		if (err == -ENOENT)
			err = 0;
		return err;
	}

	memset(&a, 0, sizeof(struct dnet_addr_cmd));

	memcpy(a.cmd.id, n->id, DNET_ID_SIZE);
	a.cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);

	a.a.cmd = DNET_CMD_JOIN;
	a.a.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd) - sizeof(struct dnet_attr);

	memcpy(&a.addr.addr, &n->addr, sizeof(struct dnet_addr));
	a.addr.sock_type = n->sock_type;
	a.addr.proto = n->proto;

	dnet_convert_addr_cmd(&a);

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == n->st)
			continue;

		if (!all && st->join_state != DNET_REJOIN)
			continue;

		pthread_mutex_lock(&st->lock);
		err = dnet_send(st, &a, sizeof(struct dnet_addr_cmd));
		if (err) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to update state", dnet_dump_id(n->id));
			dnet_log_append(n, DNET_LOG_ERROR, " %s -> %s:%d.\n", dnet_dump_id(st->id),
				dnet_server_convert_dnet_addr(&st->addr));
			pthread_mutex_unlock(&st->lock);
			break;
		}

		st->join_state = DNET_JOINED;
		pthread_mutex_unlock(&st->lock);
	}
	pthread_mutex_unlock(&n->state_lock);

	return err;
}

int dnet_join(struct dnet_node *n)
{
	int err;

	err = dnet_rejoin(n, 1);
	if (err)
		return err;

	n->join_state = DNET_JOINED;
	return 0;
}

int dnet_setup_root(struct dnet_node *n, char *root)
{
	int err;

	if (n->root) {
		free(n->root);
		close(n->rootfd);
	}

	n->root = strdup(root);
	if (!n->root) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to duplicate root string '%s'.\n", dnet_dump_id(n->id), root);
		goto err_out_exit;
	}

	n->rootfd = open(n->root, O_RDONLY);
	if (n->rootfd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open root '%s' for writing", dnet_dump_id(n->id), root);
		goto err_out_free;
	}

	n->root_len = strlen(n->root);

	err = fchdir(n->rootfd);
	if (err) {
		err = -errno;
		dnet_log_err(n, "%s: failed to change current dir to root '%s' directory", dnet_dump_id(n->id), root);
		goto err_out_close;
	}

	return 0;

err_out_close:
	close(n->rootfd);
	n->rootfd = 0;
err_out_free:
	free(n->root);
	n->root = NULL;
err_out_exit:
	return err;
}

static void dnet_io_complete(struct dnet_wait *w, int status)
{
	if (!status)
		w->status = status;
	w->cond--;
}

static int dnet_write_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;

	if (!cmd || !cmd->status || cmd->size == 0) {
		struct dnet_wait *w = priv;

		if (cmd && st) {
			err = cmd->status;
			dnet_log(st->n, DNET_LOG_INFO, "%s: completed: status: %d.\n",
				dnet_dump_id(cmd->id), cmd->status);
		}

		dnet_wakeup(w, dnet_io_complete(w, err));
		dnet_wait_put(w);
	} else
		err = cmd->status;

	return err;
}

static struct dnet_trans *dnet_io_trans_create(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	int err;
	struct dnet_attr *a;
	struct dnet_io_attr *io;
	struct dnet_cmd *cmd;
	uint64_t size = ctl->io.size;

	t = malloc(sizeof(struct dnet_trans) +
			sizeof(struct dnet_attr) +
			sizeof(struct dnet_io_attr) +
			sizeof(struct dnet_cmd));
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete_destroy;
	}
	t->data = NULL;
	t->st = NULL;
	t->complete = ctl->complete;
	t->priv = ctl->priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);
	io = (struct dnet_io_attr *)(a + 1);

	if (ctl->cmd == DNET_CMD_READ)
		size = 0;

	memcpy(cmd->id, ctl->id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;

	a->cmd = ctl->cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = ctl->aflags;

	memcpy(io, &ctl->io, sizeof(struct dnet_io_attr));

	t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	return t;

err_out_complete_destroy:
	if (ctl->complete)
		ctl->complete(NULL, NULL, NULL, ctl->priv);
	goto err_out_exit;

err_out_destroy:
	dnet_trans_destroy(t);
err_out_exit:
	return NULL;
}

static int dnet_trans_create_send(struct dnet_node *n, struct dnet_io_control *ctl)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err;
	uint64_t size = (ctl->cmd == DNET_CMD_READ) ? 0 : ctl->io.size;

	t = dnet_io_trans_create(n, ctl);
	if (!t) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to create transaction.\n", dnet_dump_id(ctl->id));
		goto err_out_exit;
	}

	dnet_log(n, DNET_LOG_INFO, "cmd: %u, size: %llu, offset: %llu, ",
			ctl->cmd, (unsigned long long)ctl->io.size, (unsigned long long)ctl->io.offset);
	dnet_log_append(n, DNET_LOG_INFO, "%s <-> ", dnet_dump_id(ctl->id));
	dnet_log_append(n, DNET_LOG_INFO, "%s.\n", dnet_dump_id(t->st->id));

	if (ctl->fd >= 0)
		return dnet_sendfile_data(t->st, ctl->fd, ctl->io.offset, size,
			t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd));

	st = t->st;
	pthread_mutex_lock(&st->lock);
	err = dnet_send(st, t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd));
	if (err)
		goto err_out_unlock;
	
	err = dnet_send(st, ctl->data, size);
	if (err)
		goto err_out_unlock;
	pthread_mutex_unlock(&st->lock);

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&st->lock);
	dnet_trans_destroy(t);
err_out_exit:
	return err;
}

int dnet_write_object(struct dnet_node *n, struct dnet_io_control *ctl, void *remote, unsigned int len)
{
	int pos = 0, err;
	unsigned int io_flags = ctl->io.flags;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, ctl->data, ctl->io.size, ctl->id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			goto err_out_complete;
		}

		ctl->io.flags = io_flags & ~DNET_IO_FLAGS_UPDATE;
		memcpy(ctl->io.id, ctl->id, DNET_ID_SIZE);

		err = dnet_trans_create_send(n, ctl);
		if (err)
			goto err_out_continue;

		pos--;
		rsize = DNET_ID_SIZE;
		err = dnet_transform(n, remote, len, ctl->id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			goto err_out_complete;
		}

		ctl->io.flags = io_flags;
		err = dnet_trans_create_send(n, ctl);
		if (err)
			goto err_out_continue;

		continue;

err_out_complete:
		if (ctl->complete)
			ctl->complete(NULL, NULL, NULL, ctl->priv);
err_out_continue:
		continue;
	}

	return pos*2;
}

int dnet_write_file(struct dnet_node *n, char *file, off_t offset, size_t size, unsigned int io_flags, unsigned int aflags)
{
	int fd, err, i, tnum;
	struct stat stat;
	int error = -ENOENT;
	struct dnet_wait *w;
	struct dnet_io_control ctl;

	w = dnet_wait_alloc(1);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting structure.\n");
		goto err_out_exit;
	}

	fd = open(file, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "Failed to open to be written file '%s'", file);
		goto err_out_put;
	}

	if (!size) {
		err = fstat(fd, &stat);
		if (err) {
			err = -errno;
			dnet_log_err(n, "Failed to stat to be written file '%s'", file);
			goto err_out_close;
		}

		size = stat.st_size;
	}

	ctl.data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (ctl.data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "Failed to map to be written file '%s'", file);
		goto err_out_close;
	}

	tnum = n->trans_num*2;

	for (i=0; i<tnum; ++i)
		dnet_wait_get(w);

	pthread_mutex_lock(&w->wait_lock);
	w->cond += tnum;
	pthread_mutex_unlock(&w->wait_lock);

	ctl.fd = fd;

	ctl.complete = dnet_write_complete;
	ctl.priv = w;

	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = aflags;

	ctl.io.flags = io_flags;
	ctl.io.size = size;
	ctl.io.offset = offset;

	err = dnet_write_object(n, &ctl, file, strlen(file));
	if (err <= 0)
		goto err_out_unmap;

	munmap(ctl.data, size);

	dnet_wakeup(w, w->cond -= tnum - err + 1);

	err = dnet_wait_event(w, w->cond == 0, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;

		dnet_log(n, DNET_LOG_ERROR, "Failed to write file '%s' into the storage, err: %d.\n", file, err);
		error = err;
	}

	dnet_log(n, DNET_LOG_INFO, "Successfully wrote file: '%s' into the storage, size: %zu.\n", file, size);

	close(fd);
	dnet_wait_put(w);

	return error;

err_out_unmap:
	munmap(ctl.data, size);
err_out_close:
	close(fd);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv)
{
	int fd, err, freeing = 0;
	struct dnet_node *n = st->n;
	struct dnet_io_completion *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (!cmd) {
		err = -ENOMEM;
		freeing = 1;
		goto err_out_exit;
	}

	if (cmd->status != 0 || cmd->size == 0) {
		err = cmd->status;
		freeing = 1;

		dnet_log(n, DNET_LOG_INFO, "%s: read completed: file: '%s', status: %d.\n",
				dnet_dump_id(cmd->id), c->file, cmd->status);
		goto err_out_exit;
	}

	if (cmd->flags & DNET_FLAGS_DESTROY) {
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		dnet_log(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(a + 1);
	data = io + 1;

	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	fd = open(c->file, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open read completion file '%s'", dnet_dump_id(cmd->id), c->file);
		goto err_out_exit;
	}

	err = pwrite(fd, data, io->size, io->offset);
	if (err <= 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to write data into completion file '%s'", dnet_dump_id(cmd->id), c->file);
		goto err_out_close;
	}

	fsync(fd);
	close(fd);
	dnet_log(n, DNET_LOG_INFO, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status);

	return cmd->status;

err_out_close:
	dnet_log(n, DNET_LOG_ERROR, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status, err);
err_out_exit:
	if (c->wait) {
		dnet_wakeup(c->wait, c->wait->cond = err);
		dnet_wait_put(c->wait);
	}

	if (freeing)
		free(c);
	return err;
}

int dnet_read_object(struct dnet_node *n, struct dnet_io_control *ctl)
{
	int err;

	err = dnet_trans_create_send(n, ctl);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to read object %s, err: %d.\n", dnet_dump_id(ctl->id), err);
		return err;
	}

	return 0;
}

int dnet_read_file(struct dnet_node *n, char *file, uint64_t offset, uint64_t size, unsigned int aflags)
{
	int err, len = strlen(file), pos = 0, wait_init = ~0, error = 0;
	struct dnet_io_completion *c;
	struct dnet_wait *w;
	struct dnet_io_control ctl;

	w = dnet_wait_alloc(wait_init);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, DNET_LOG_ERROR, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	ctl.io.size = size;
	ctl.io.offset = offset;
	ctl.io.flags = 0;

	ctl.fd = -1;
	ctl.aflags = aflags;
	ctl.complete = dnet_read_complete;
	ctl.cmd = DNET_CMD_READ;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, ctl.io.id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		c = malloc(sizeof(struct dnet_io_completion) + len + 1 + sizeof(DNET_HISTORY_SUFFIX));
		if (!c) {
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to allocate IO completion structure for '%s' file reading.\n",
					dnet_dump_id(ctl.io.id), file);
			err = -ENOMEM;
			goto err_out_put;
		}

		c->wait = dnet_wait_get(w);
		c->offset = offset;
		c->size = size;
		c->file = (char *)(c + 1);

		if (aflags)
			sprintf(c->file, "%s%s", file, DNET_HISTORY_SUFFIX);
		else
			sprintf(c->file, "%s", file);

		memcpy(ctl.id, ctl.io.id, DNET_ID_SIZE);

		ctl.priv = c;

		w->cond = wait_init;
		err = dnet_read_object(n, &ctl);
		if (err)
			continue;

		err = dnet_wait_event(w, w->cond != wait_init, &n->wait_ts);
		if (err || (w->cond != 0 && w->cond != wait_init)) {
			if (!err) {
				err = w->cond;
				error = err;
			}
			dnet_log(n, DNET_LOG_ERROR, "%s: failed to wait for '%s' read completion, err: %d.\n",
					dnet_dump_id(ctl.io.id), file, err);
			continue;
		}

		error = 0;
		break;
	}

	dnet_wait_put(w);

	return error;

err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* init)(void *priv),
	int (* update)(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags),
	int (* final)(void *priv, void *dst, unsigned int *dsize, unsigned int flags))
{
	struct dnet_transform *t;
	int err = 0;

	if (!n || !init || !update || !final || !name) {
		err = -EINVAL;
		goto err_out_exit;
	}

	pthread_mutex_lock(&n->tlock);
	list_for_each_entry(t, &n->tlist, tentry) {
		if (!strncmp(name, t->name, DNET_MAX_NAME_LEN)) {
			err = -EEXIST;
			goto err_out_unlock;
		}
	}

	t = malloc(sizeof(struct dnet_transform));
	if (!t) {
		err = -ENOMEM;
		goto err_out_unlock;
	}

	memset(t, 0, sizeof(struct dnet_transform));

	snprintf(t->name, sizeof(t->name), "%s", name);
	t->init = init;
	t->update = update;
	t->final = final;
	t->priv = priv;

	list_add_tail(&t->tentry, &n->tlist);
	n->trans_num++;

	pthread_mutex_unlock(&n->tlock);

	return 0;

err_out_unlock:
	pthread_mutex_unlock(&n->tlock);
err_out_exit:
	return err;
}

int dnet_remove_transform(struct dnet_node *n, char *name)
{
	struct dnet_transform *t, *tmp;
	int err = -ENOENT;

	if (!n)
		return -EINVAL;

	pthread_mutex_lock(&n->tlock);
	list_for_each_entry_safe(t, tmp, &n->tlist, tentry) {
		if (!strncmp(name, t->name, DNET_MAX_NAME_LEN)) {
			err = 0;
			break;
		}
	}

	if (!err) {
		n->trans_num--;
		list_del(&t->tentry);
		free(t);
	}
	pthread_mutex_unlock(&n->tlock);

	return err;
}

struct dnet_wait *dnet_wait_alloc(int cond)
{
	int err;
	struct dnet_wait *w;

	w = malloc(sizeof(struct dnet_wait));
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	memset(w, 0, sizeof(struct dnet_wait));

	err = pthread_cond_init(&w->wait, NULL);
	if (err)
		goto err_out_exit;

	err = pthread_mutex_init(&w->wait_lock, NULL);
	if (err)
		goto err_out_destroy;

	w->cond = cond;
	w->refcnt = 1;

	return w;

err_out_destroy:
	pthread_mutex_destroy(&w->wait_lock);
err_out_exit:
	return NULL;
}

void dnet_wait_destroy(struct dnet_wait *w)
{
	if (w->refcnt == 0) {
		pthread_mutex_destroy(&w->wait_lock);
		pthread_cond_destroy(&w->wait);
	}
}

static void __dnet_send_cmd_complete(struct dnet_wait *w, int status)
{
	w->status = status;
	w->cond = 1;
}

static int dnet_send_cmd_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused, void *priv)
{
	int err = -EINVAL;

	if (!cmd || cmd->size == 0 || !cmd->status) {
		struct dnet_wait *w = priv;

		if (cmd) {
			dnet_log(st->n, DNET_LOG_INFO, "%s: completed command, err: %d.\n",
				dnet_dump_id(cmd->id), cmd->status);
			err = cmd->status;
		}

		dnet_wakeup(w, __dnet_send_cmd_complete(w, err));
		dnet_wait_put(w);
	} else
		err = cmd->status;

	return err;
}

int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err, len = strlen(command);
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_wait *w;

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	t = malloc(sizeof(struct dnet_trans) + sizeof(struct dnet_cmd) + sizeof(struct dnet_attr));
	if (!t) {
		err = -ENOMEM;
		goto err_out_put;
	}

	t->data = NULL;
	t->st = NULL;
	t->complete = dnet_send_cmd_complete;
	t->priv = dnet_wait_get(w);

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr) + len;
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;

	a->cmd = DNET_CMD_EXEC;
	a->size = len;
	a->flags = 0;

	sprintf((char *)(a+1), "%s", command);
	
	st = t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;

	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	pthread_mutex_lock(&st->lock);
	err = dnet_send(st, t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_cmd) + len);
	if (err)
		goto err_out_unlock;
	pthread_mutex_unlock(&st->lock);

	err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;

		dnet_log(n, DNET_LOG_ERROR, "%s: failed to execute command '%s', err: %d.\n", dnet_dump_id(id), command, err);
		goto err_out_put;
	}

	dnet_wait_put(w);
	
	dnet_log(n, DNET_LOG_INFO, "%s: successfully executed command '%s'.\n", dnet_dump_id(id), command);
	return 0;

err_out_unlock:
	pthread_mutex_unlock(&st->lock);
err_out_destroy:
	dnet_trans_destroy(t);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_give_up_control(struct dnet_node *n)
{
	while (!n->need_exit) {
		if (n->join_state == DNET_REJOIN) {
			dnet_rejoin(n, 0);
			n->join_state = DNET_JOINED;
		}
		sleep(1);
	}

	return 0;
}

int dnet_lookup_object(struct dnet_node *n, unsigned char *id,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv)
{
	struct dnet_trans *t;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_net_state *st;
	int err;

	t = malloc(sizeof(struct dnet_trans) +
			sizeof(struct dnet_attr) +
			sizeof(struct dnet_cmd));
	if (!t) {
		err = -ENOMEM;
		goto err_out_complete_destroy;
	}
	t->data = NULL;
	t->st = NULL;
	t->complete = complete;
	t->priv = priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr);
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;

	a->cmd = DNET_CMD_LOOKUP;
	a->size = 0;
	a->flags = 0;

	t->st = dnet_state_get_first(n, cmd->id, n->st);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, DNET_LOG_ERROR, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
		goto err_out_destroy;
	}

	err = dnet_trans_insert(t);
	if (err)
		goto err_out_destroy;

	cmd->trans = t->trans;
	dnet_convert_cmd(cmd);
	dnet_convert_attr(a);

	st = t->st;

	dnet_log(n, DNET_LOG_NOTICE, "%s: lookup to: ", dnet_dump_id(id));
	dnet_log_append(n, DNET_LOG_NOTICE, "%s.\n", dnet_dump_id(st->id));

	pthread_mutex_lock(&st->lock);
	err = dnet_send(st, t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_cmd));
	if (err)
		goto err_out_unlock;
	pthread_mutex_unlock(&st->lock);

	return 0;

err_out_complete_destroy:
	if (complete)
		complete(NULL, NULL, NULL, priv);
	free(priv);
	goto err_out_exit;

err_out_unlock:
	pthread_mutex_unlock(&st->lock);
err_out_destroy:
	dnet_trans_destroy(t);
err_out_exit:
	return err;
}

int dnet_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	struct dnet_wait *w = priv;
	struct dnet_node *n = NULL;
	struct dnet_net_state *nst;
	struct dnet_addr_attr *a;
	int err, s;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}
	n = st->n;

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (attr->size != sizeof(struct dnet_addr_attr)) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: wrong dnet_addr attribute size %llu, must be %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_addr_attr));
		err = -EPROTO;
		goto err_out_exit;
	}

	a = (struct dnet_addr_attr *)(attr + 1);

	dnet_convert_addr_attr(a);

	dnet_log(n, DNET_LOG_INFO, "%s: lookup returned address %s.\n",
			dnet_dump_id(cmd->id), dnet_server_convert_dnet_addr(&a->addr));

	s = dnet_socket_create_addr(n, a->sock_type, a->proto,
			(struct sockaddr *)&a->addr.addr, a->addr.addr_len, 0);
	if (s < 0) {
		err = s;
		goto err_out_exit;
	}

	nst = dnet_state_create(n, cmd->id, &a->addr, s, dnet_state_process);
	if (!nst) {
		err = -EINVAL;
		goto err_out_sock_close;
	}

	dnet_log(n, DNET_LOG_NOTICE, "%s: lookup complete: added state %s.\n", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

err_out_sock_close:
	close(s);
err_out_exit:
	if (n)
		dnet_log(n, DNET_LOG_ERROR, "%s: status: %d.\n", dnet_dump_id(cmd->id), cmd->status);
	if (w) {
		dnet_wakeup(w, w->cond = 1);
		dnet_wait_put(w);
	}
	return err;
}

int dnet_lookup(struct dnet_node *n, char *file)
{
	int err, pos = 0, len = strlen(file), error = 0;
	struct dnet_wait *w;
	unsigned char id[DNET_ID_SIZE];

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		err = dnet_lookup_object(n, id, dnet_lookup_complete, dnet_wait_get(w));
		if (err) {
			error = err;
			continue;
		}

		err = dnet_wait_event(w, w->cond == 1, &n->wait_ts);
		if (err || w->status) {
			if (!err)
				err = w->status;
			error = err;
			continue;
		}

		error = 0;
		break;
	}

	dnet_wait_put(w);
	return error;

err_out_exit:
	return err;
}
