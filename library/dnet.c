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

static int dnet_transform_file(struct dnet_node *n, char *file, off_t offset, size_t size,
		void *dst, unsigned int *dsize, int *ppos)
{
	int err = -ENOENT;
	int fd;
	void *data;

	fd = open(file, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open file '%s' for the transformation",
				dnet_dump_id(n->id), file);
		goto err_out_exit;
	}

	if (!size) {
		struct stat st;

		err = fstat(fd, &st);
		if (err < 0) {
			err = -errno;
			dnet_log_err(n, "%s: failed to stat file '%s' for the transformation",
					dnet_dump_id(n->id), file);
			goto err_out_close;
		}

		size = st.st_size;
	}

	data = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	if (data == MAP_FAILED) {
		err = -errno;
		dnet_log_err(n, "%s: failed to map file '%s' for the transformation",
				dnet_dump_id(n->id), file);
		goto err_out_close;
	}

	err = dnet_transform(n, data, size, dst, dsize, ppos);
	if (err)
		goto err_out_unmap;

	munmap(data, size);
	close(fd);

	return 0;

err_out_unmap:
	munmap(data, size);
err_out_close:
	close(fd);
err_out_exit:
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
		st = dnet_state_get(orig);

	memcpy(&l.cmd.id, st->id, DNET_ID_SIZE);
	l.cmd.size = sizeof(struct dnet_addr_cmd) - sizeof(struct dnet_cmd);
	l.cmd.trans |= DNET_TRANS_REPLY;

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

	st = dnet_state_create(n, cmd->id, &a->addr, s, dnet_state_process, 1);
	if (!st) {
		err = -EINVAL;
		goto err_out_close;
	}

	dnet_log(n, "%s: state %s.\n", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));

	return 0;

err_out_close:
	close(s);
err_out_exit:
	dnet_log(n, "%s: state %s -> ", dnet_dump_id(cmd->id),
		dnet_server_convert_dnet_addr(&a->addr));
	if (st)
		dnet_log_append(n, "%s, .\n", dnet_dump_id(st->id));
	dnet_log_append(n, "err: %d.\n", err);
	return err;
}

static int dnet_update_history(struct dnet_node *n, int md, unsigned char *id, struct dnet_io_attr *io, int tmp)
{
	char history[DNET_ID_SIZE*2+1 + sizeof(DNET_HISTORY_SUFFIX) + 5];
	int fd, err;

	snprintf(history, sizeof(history), "%s%s%s", dnet_dump_id(id), DNET_HISTORY_SUFFIX, (tmp)?".tmp":"");

	fd = openat(md, history, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open history file '%s'", dnet_dump_id(id), history);
		goto err_out_exit;
	}

	err = write(fd, io, sizeof(struct dnet_io_attr));
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
	int err, dd, md;
	struct dnet_node *n = st->n;
	char dir[3];
	struct dnet_io_attr *io = data;
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE;
	char file[DNET_ID_SIZE * 2 + 1];
	
	if (attr->size <= sizeof(struct dnet_io_attr)) {
		dnet_log(n, "%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %u.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size, sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	if ((io->size != attr->size - sizeof(struct dnet_io_attr)) ||
			(io->size > cmd->size)){
		dnet_log(n, "%s: wrong io size: %llu, must be equal to %llu.\n",
				dnet_dump_id(cmd->id), io->size,
				(unsigned long long)attr->size - sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!n->root) {
		dnet_log(n, "%s: can not write without root dir.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	snprintf(dir, sizeof(dir), "%02x", cmd->id[0]);

	err = mkdirat(n->rootfd, dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_log_err(n, "%s: faliled to create dir '%s' in the root '%s'",
					dnet_dump_id(cmd->id), dir, n->root);
			goto err_out_exit;
		}
	}

	md = openat(n->rootfd, dir, O_RDONLY);
	if (md < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open dir '%s/%s'",
				dnet_dump_id(cmd->id), n->root, dir);
		goto err_out_exit;
	}

	snprintf(file, sizeof(file), "%s", dnet_dump_id(cmd->id));

	if (io->flags & DNET_IO_FLAGS_APPEND)
		oflags |= O_APPEND;

	dd = openat(md, file, oflags, 0644);
	if (dd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open data file '%s/%s/%s'",
				dnet_dump_id(cmd->id), n->root, dir, file);
		goto err_out_close_md;
	}

	err = pwrite(dd, data, io->size, io->offset);
	if (err <= 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to write into '%s/%s/%s'",
			dnet_dump_id(cmd->id), n->root, dir, file);
		goto err_out_close_dd;
	}

	if (io->flags & DNET_IO_FLAGS_UPDATE) {
		err = dnet_update_history(n, md, cmd->id, io, 0);
		if (err) {
			dnet_log(n, "%s: failed to update history for '%s/%s/%s'",
				dnet_dump_id(cmd->id), n->root, dir, file);
			goto err_out_close_dd;
		}
	}

	dnet_log(n, "%s: IO file: '%s/%s/%s', offset: %llu, size: %llu.\n",
			dnet_dump_id(cmd->id), n->root, dir, file,
			io->offset, io->size);

	fsync(dd);
	close(dd);
	close(md);

	return 0;

err_out_close_dd:
	close(dd);
err_out_close_md:
	close(md);
err_out_exit:
	return err;
}

static int dnet_cmd_read(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_node *n = st->n;
	struct dnet_io_attr *io = data;
	char file[DNET_ID_SIZE * 2 + 1 + 4];
	int dd, err;
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_io_attr *rio;
	size_t size;
	off_t offset;
	uint64_t total_size;

	if (attr->size != sizeof(struct dnet_io_attr)) {
		dnet_log(n, "%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %u.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);

	snprintf(file, sizeof(file), "%02x/%s", io->id[0], dnet_dump_id(io->id));

	dd = openat(n->rootfd, file, O_RDONLY, 0644);
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
		dnet_log(n, "%s: failed to allocate reply attributes.\n", dnet_dump_id(io->id));
		goto err_out_close_dd;
	}

	total_size = size;
	offset = io->offset;

	while (total_size) {
		size = total_size;
		if (size > DNET_MAX_READ_TRANS_SIZE)
			size = DNET_MAX_READ_TRANS_SIZE;

		dnet_log(n, "%s: offset: %llu, size: %zu, c: %p.\n", dnet_dump_id(io->id),
				(unsigned long long)io->offset, size, c);

		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->id, DNET_ID_SIZE);
		c->flags = DNET_FLAGS_MORE;
		c->status = 0;
		c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
		c->trans = cmd->trans | DNET_TRANS_REPLY;

		a->cmd = DNET_CMD_READ;
		a->size = sizeof(struct dnet_io_attr) + size;
		a->flags = 0;

		memcpy(rio->id, io->id, DNET_ID_SIZE);
		rio->size = size;
		rio->offset = offset;
		rio->flags = 0;

		dnet_convert_cmd(c);
		dnet_convert_attr(a);
		dnet_convert_io_attr(rio);

		err = dnet_sendfile_data(st, file, dd, offset, size,
			c, sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		if (err) {
			dnet_log(n, "%s: failed to send read reply.\n", dnet_dump_id(io->id));
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

	dnet_log(n, "%s: command: '%s'.\n", dnet_dump_id(cmd->id), command);

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
			dnet_log_err(n, "%s: failed to wait for child (%d) process", dnet_dump_id(cmd->id), pid);
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
		unsigned int sz;

		dnet_convert_attr(a);
		sz = a->size;

		if (size < sizeof(struct dnet_attr)) {
			dnet_log(st->n, "%s: 1 wrong cmd: size: %llu/%llu, attr_size: %u.\n",
					dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EPROTO;
			break;
		}

		data += sizeof(struct dnet_attr);
		size -= sizeof(struct dnet_attr);
		
		if (size < a->size) {
			dnet_log(n, "%s: 2 wrong cmd: size: %llu/%llu, attr_size: %u.\n",
				dnet_dump_id(st->id), (unsigned long long)cmd->size, size, sz);
			err = -EPROTO;
			break;
		}

		dnet_log(n, "%s: trans: %llu, size_left: %llu, starting cmd: %u, asize: %llu.\n",
			dnet_dump_id(cmd->id), cmd->trans, size, a->cmd, (unsigned long long)a->size);

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

		dnet_log(n, "%s: trans: %llu, size_left: %llu, completed cmd: %u, asize: %llu, err: %d.\n",
			dnet_dump_id(cmd->id), cmd->trans, size, a->cmd, (unsigned long long)a->size, err);

		if (err)
			break;

		if (size < sz) {
			dnet_log(n, "%s: 3 wrong cmd: size: %llu/%llu, attr_size: %u.\n",
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
		ack.flags = cmd->flags;
		ack.status = err;

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
		dnet_log(n, "%s: failed to send reverse lookup message to %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	err = dnet_recv(st, &acmd, sizeof(acmd));
	if (err < 0) {
		dnet_log(n, "%s: failed to receive reverse lookup response from %s, err: %d.\n",
				dnet_dump_id(n->id),
				dnet_server_convert_dnet_addr(&addr), err);
		goto err_out_sock_close;
	}

	dnet_convert_addr_cmd(&acmd);

	dnet_log(n, "%s: reverse lookup: ", dnet_dump_id(n->id));
	dnet_log_append(n, "%s -> %s.\n", dnet_dump_id(acmd.cmd.id),
		dnet_server_convert_dnet_addr(&acmd.addr.addr));

	st = dnet_state_create(n, acmd.cmd.id, &acmd.addr.addr, s, dnet_state_process, 0);
	if (!st)
		goto err_out_sock_close;

	return 0;

err_out_sock_close:
	close(s);
err_out_exit:
	return err;
}

int dnet_join(struct dnet_node *n)
{
	struct dnet_addr_cmd a;
	int err = 0;
	struct dnet_net_state *st;

	if (!n->root) {
		dnet_log(n, "%s: can not join without root directory to store data.\n", dnet_dump_id(n->id));
		return -EINVAL;
	}

	/*
	 * Need to sync local content.
	 */
	err = dnet_recv_list(n);
	if (err) {
		dnet_log(n, "%s: content sync failed, error: %d.\n", dnet_dump_id(n->id), err);
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

		err = dnet_send(st, &a, sizeof(struct dnet_addr_cmd));
		if (err) {
			dnet_log(n, "%s: failed to update state", dnet_dump_id(n->id));
			dnet_log_append(n, " %s -> %s:%d.\n", dnet_dump_id(st->id),
				dnet_server_convert_dnet_addr(&st->addr));
			break;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	return err;
}

int dnet_setup_root(struct dnet_node *n, char *root)
{
	if (n->root) {
		free(n->root);
		close(n->rootfd);
	}

	n->root = strdup(root);
	if (!n->root) {
		dnet_log(n, "%s: failed to duplicate root string '%s'.\n", dnet_dump_id(n->id), root);
		return -ENOMEM;
	}

	n->rootfd = open(n->root, O_RDONLY);
	if (n->rootfd < 0) {
		int err = -errno;
		dnet_log_err(n, "%s: failed to open root '%s' for writing", dnet_dump_id(n->id), root);
		n->rootfd = 0;
		return err;
	}

	return 0;
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
	struct dnet_io_completion *c = priv;

	if (!cmd->status || cmd->size == 0) {
		dnet_log(st->n, "%s: completed: file: '%s', status: %d.\n",
			dnet_dump_id(cmd->id), c->file, cmd->status);
		dnet_wakeup(c->wait, dnet_io_complete(c->wait, cmd->status));
		dnet_wait_put(c->wait);
	}

	return cmd->status;
}

static struct dnet_trans *dnet_io_trans_create(struct dnet_node *n, unsigned char *id,
		int attr_cmd, struct dnet_io_attr *ioattr,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv)
{
	struct dnet_trans *t;
	int err;
	struct dnet_attr *a;
	struct dnet_io_attr *io;
	struct dnet_cmd *cmd;
	uint64_t size = ioattr->size;

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
	t->complete = complete;
	t->priv = priv;

	cmd = (struct dnet_cmd *)(t + 1);
	a = (struct dnet_attr *)(cmd + 1);
	io = (struct dnet_io_attr *)(a + 1);

	memcpy(cmd->id, id, DNET_ID_SIZE);
	cmd->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
	cmd->flags = DNET_FLAGS_NEED_ACK;
	cmd->status = 0;

	a->cmd = attr_cmd;
	a->size = sizeof(struct dnet_io_attr) + size;
	a->flags = 0;

	memcpy(io, ioattr, sizeof(struct dnet_io_attr));

	t->st = dnet_state_get_first(n, n->st);
	if (!t->st) {
		dnet_log(n, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
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
	if (complete)
		complete(NULL, NULL, NULL, priv);
	free(priv);
	goto err_out_exit;

err_out_destroy:
	dnet_trans_destroy(t);
err_out_exit:
	return NULL;
}

int dnet_write_file(struct dnet_node *n, char *file, off_t offset, size_t size, int append)
{
	int fd, err, pos = 0, len = strlen(file);
	struct dnet_trans *t;
	struct dnet_io_attr io;
	unsigned char file_id[DNET_ID_SIZE];
	struct stat stat;
	struct dnet_net_state *st;
	int error = -ENOENT;
	struct dnet_wait *w;
	struct dnet_io_completion *c;

	w = dnet_wait_alloc(1);
	if (!w) {
		err = -ENOMEM;
		dnet_log(n, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	fd = openat(n->rootfd, file, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		err = -errno;
		dnet_log_err(n, "%s: failed to open file '%s'", dnet_dump_id(n->id), file);
		goto err_out_put;
	}

	if (!size) {
		err = fstatat(n->rootfd, file, &stat, AT_SYMLINK_NOFOLLOW);
		if (err) {
			err = -errno;
			dnet_log_err(n, "%s: failed to stat file '%s'", dnet_dump_id(n->id), file);
			goto err_out_close;
		}

		size = stat.st_size;
	}

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, file_id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}
		pos--;

		rsize = DNET_ID_SIZE;
		err = dnet_transform_file(n, file, offset, size, io.id, &rsize, &pos);
		if (err)
			continue;

		io.size = size;
		io.offset = offset;
		io.flags = DNET_IO_FLAGS_UPDATE;

		if (append)
			io.flags |= DNET_IO_FLAGS_APPEND;

		c = malloc(sizeof(struct dnet_io_completion) + len + 1);
		if (!c) {
			dnet_log(n, "%s: failed to allocate IO completion structure for '%s' file reading.\n",
					dnet_dump_id(io.id), file);
			err = -ENOMEM;
			goto err_out_put;
		}

		c->wait = dnet_wait_get(w);
		c->offset = offset;
		c->size = size;
		c->file = (char *)(c + 1);
		sprintf(c->file, "%s", file);

		pthread_mutex_lock(&w->wait_lock);
		w->cond++;
		pthread_mutex_unlock(&w->wait_lock);

		t = dnet_io_trans_create(n, file_id, DNET_CMD_WRITE, &io, dnet_write_complete, c);
		if (!t) {
			dnet_log(n, "%s: failed to create transaction.\n", dnet_dump_id(io.id));
			continue;
		}

		st = t->st;
		dnet_log(n, "file: '%s' -> %s.\n", file, dnet_dump_id(st->id));

		err = dnet_sendfile_data(st, file, fd, 0, size,
			t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd));
		if (!err)
			error = 0;
	}

	dnet_wakeup(w, w->cond--);

	err = dnet_wait_event(w, w->cond == 0, &n->wait_ts);
	if (err || w->status) {
		if (!err)
			err = w->status;

		dnet_log(n, "%s: failed to write file '%s', err: %d.\n", dnet_dump_id(n->id), file, err);
		error = err;
	}

	dnet_log(n, "%s: file: '%s', size: %llu.\n", dnet_dump_id(io.id), file, (unsigned long long)stat.st_size);

	close(fd);
	dnet_wait_put(w);

	return error;

err_out_close:
	close(fd);
err_out_put:
	dnet_wait_put(w);
err_out_exit:
	return err;
}

int dnet_write_object(struct dnet_node *n, unsigned char *id, struct dnet_io_attr *io,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv, void *data)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err;

	t = dnet_io_trans_create(n, id, DNET_CMD_WRITE, io, complete, priv);
	if (!t) {
		err = -ENOMEM;
		dnet_log(n, "%s: failed to create transaction.\n", dnet_dump_id(id));
		goto err_out_exit;
	}

	st = t->st;

	dnet_log(n, "Write transaction: object: %s ", dnet_dump_id(id));
	dnet_log_append(n, "update: %s, offset: %llu, size: %llu -> ", dnet_dump_id(io->id), io->offset, io->size);
	dnet_log_append(n, "%s.\n", dnet_dump_id(st->id));

	pthread_mutex_lock(&st->lock);

	err = dnet_send(st, t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd));
	if (err)
		goto err_out_unlock;

	err = dnet_send(st, data, io->size);
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

int dnet_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd, struct dnet_attr *a, void *priv)
{
	int fd, err;
	struct dnet_node *n = st->n;
	struct dnet_io_completion *c = priv;
	struct dnet_io_attr *io;
	void *data;

	if (!cmd) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	if (cmd->status != 0 || cmd->size == 0) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (cmd->flags & DNET_FLAGS_DESTROY) {
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log(n, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %u.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		dnet_log(n, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(a + 1);
	data = io + 1;

	dnet_convert_attr(a);
	dnet_convert_io_attr(io);

	fd = openat(st->n->rootfd, c->file, O_RDWR | O_CREAT, 0644);
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
	dnet_log(n, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status);

	return cmd->status;

err_out_close:
	dnet_log(n, "%s: read completed: file: '%s', offset: %llu, size: %llu, status: %d, err: %d.\n",
			dnet_dump_id(cmd->id), c->file, (unsigned long long)io->offset,
			(unsigned long long)io->size, cmd->status, err);
err_out_exit:
	if (c->wait) {
		dnet_wakeup(c->wait, c->wait->cond = err);
		dnet_wait_put(c->wait);
	}
	return err;
}

int dnet_read_object(struct dnet_node *n, struct dnet_io_attr *io,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *), void *priv)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err;

	t = dnet_io_trans_create(n, io->id, DNET_CMD_READ, io, complete, priv);
	if (!t) {
		dnet_log(n, "%s: failed to create transaction.\n", dnet_dump_id(io->id));
		err = -ENOMEM;
		goto err_out_exit;
	}

	st = t->st;
	dnet_log(n, "Read transaction: object: %s, ", dnet_dump_id(io->id));
	dnet_log_append(n, "offset: %llu, size: %llu, trans: %llu <- ", (unsigned long long)io->offset,
			(unsigned long long)io->size, (unsigned long long)t->trans);
	dnet_log_append(n, "%s.\n", dnet_dump_id(st->id));

	pthread_mutex_lock(&st->lock);

	err = dnet_send(st, t+1, sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_cmd));
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

int dnet_read_file(struct dnet_node *n, char *file, uint64_t offset, uint64_t size)
{
	struct dnet_io_attr io;
	int err, len = strlen(file), pos = 0, wait_init = ~0, error = 0;
	struct dnet_io_completion *c;
	struct dnet_wait *w;

	w = dnet_wait_alloc(wait_init);
	if (!w) {
		dnet_log(n, "Failed to allocate read waiting.\n");
		goto err_out_exit;
	}

	io.size = size;
	io.offset = offset;
	io.flags = 0;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, file, len, io.id, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		c = malloc(sizeof(struct dnet_io_completion) + len + 1);
		if (!c) {
			dnet_log(n, "%s: failed to allocate IO completion structure for '%s' file reading.\n",
					dnet_dump_id(io.id), file);
			err = -ENOMEM;
			goto err_out_put;
		}

		c->wait = dnet_wait_get(w);
		c->offset = offset;
		c->size = size;
		c->file = (char *)(c + 1);
		sprintf(c->file, "%s", file);

		w->cond = wait_init;
		err = dnet_read_object(n, &io, dnet_read_complete, c);
		if (err)
			continue;

		err = dnet_wait_event(w, w->cond != wait_init, &n->wait_ts);
		if (err || (w->cond != 0 && w->cond != wait_init)) {
			if (!err) {
				err = w->cond;
				error = err;
			}
			dnet_log(n, "%s: failed to wait for '%s' read completion, err: %d.\n",
					dnet_dump_id(io.id), file, err);
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

struct dnet_send_cmd_completion
{
	struct dnet_wait		*wait;
	char				*command;
};

static void __dnet_send_cmd_complete(struct dnet_wait *w, int status)
{
	w->status = status;
	w->cond = 1;
}

static int dnet_send_cmd_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
			struct dnet_attr *attr __unused, void *priv)
{
	struct dnet_send_cmd_completion *c = priv;
	struct dnet_wait *w = c->wait;

	dnet_log(st->n, "%s: completed command '%s', err: %d.\n",
			dnet_dump_id(cmd->id), c->command, cmd->status);

	if (cmd->size == 0 || !cmd->status) {
		dnet_wakeup(w, __dnet_send_cmd_complete(w, cmd->status));
		dnet_wait_put(w);
	}

	return cmd->status;
}

int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command)
{
	struct dnet_trans *t;
	struct dnet_net_state *st;
	int err, len = strlen(command) + 1;
	struct dnet_attr *a;
	struct dnet_cmd *cmd;
	struct dnet_send_cmd_completion *c;
	struct dnet_wait *w;

	c = malloc(sizeof(struct dnet_send_cmd_completion) + len);
	if (!c) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(c, 0, sizeof(struct dnet_send_cmd_completion));

	w = dnet_wait_alloc(0);
	if (!w) {
		err = -ENOMEM;
		goto err_out_free;
	}

	c->wait = dnet_wait_get(w);
	c->command = (char *)(c + 1);
	sprintf(c->command, "%s", command);

	t = malloc(sizeof(struct dnet_trans) + sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) + len);
	if (!t) {
		err = -ENOMEM;
		goto err_out_put;
	}

	t->data = NULL;
	t->st = NULL;
	t->complete = dnet_send_cmd_complete;
	t->priv = c;

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
	
	st = t->st = dnet_state_get_first(n, n->st);
	if (!t->st) {
		err = -ENOENT;
		dnet_log(n, "%s: failed to find a state.\n", dnet_dump_id(cmd->id));
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

		dnet_log(n, "%s: failed to execute command '%s', err: %d.\n", dnet_dump_id(id), command, err);
		goto err_out_put;
	}

	dnet_wait_put(w);
	
	dnet_log(n, "%s: successfully executed command '%s'.\n", dnet_dump_id(id), command);
	return 0;

err_out_unlock:
	pthread_mutex_unlock(&st->lock);
err_out_destroy:
	dnet_trans_destroy(t);
err_out_put:
	dnet_wait_put(w);
err_out_free:
	free(c);
err_out_exit:
	return err;
}
