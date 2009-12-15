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

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "backends.h"

struct file_backend_root
{
	char			*root;
	int			root_len;
	int			rootfd;
	int			sync;
	unsigned int 		bit_mask;
};

static inline void file_backend_setup_file(struct file_backend_root *r, char *file,
		unsigned int size, struct dnet_io_attr *io)
{

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		snprintf(file, size, "%x/%s%s", file_backend_get_dir(io->origin, r->bit_mask),
				dnet_dump_id_len(io->origin, DNET_ID_SIZE),
				DNET_HISTORY_SUFFIX);
	else
		snprintf(file, size, "%x/%s", file_backend_get_dir(io->origin, r->bit_mask),
				dnet_dump_id_len(io->origin, DNET_ID_SIZE));

}

void *file_backend_setup_root(char *root, int sync, unsigned int bits)
{
	int err;
	struct file_backend_root *r;

	r = malloc(sizeof(struct file_backend_root));
	if (!r)
		goto err_out_exit;

	r->root = strdup(root);
	if (!r->root) {
		err = -ENOMEM;
		fprintf(stderr, "Failed to duplicate root string '%s'.\n", root);
		goto err_out_exit;
	}

	r->rootfd = open(r->root, O_RDONLY);
	if (r->rootfd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open root '%s': %s.\n", root, strerror(errno));
		goto err_out_free;
	}

	r->root_len = strlen(r->root);
	r->sync = sync;
	r->bit_mask = ~0;
	r->bit_mask <<= sizeof(r->bit_mask) * 8 - bits;
	r->bit_mask >>= sizeof(r->bit_mask) * 8 - bits;

	err = fchdir(r->rootfd);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to change current dir to root '%s' directory: %s.\n",
				root, strerror(errno));
		goto err_out_close;
	}

	return r;

err_out_close:
	close(r->rootfd);
	r->rootfd = -1;
err_out_free:
	free(r->root);
	r->root = NULL;
err_out_exit:
	return NULL;
}

static void dnet_convert_name_to_id(char *name, unsigned char *id)
{
	int i;
	char sub[3];

	sub[2] = '\0';
	for (i=0; i<DNET_ID_SIZE; i++) {
		sub[0] = name[2*i];
		sub[1] = name[2*i + 1];
		id[i] = strtol(sub, NULL, 16);
	}
}

static int dnet_is_regular(void *state, char *path)
{
	struct stat st;
	int err;

	err = stat(path, &st);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"Failed to stat '%s' object: %s.\n",
				path, strerror(errno));
		return err;
	}

	return S_ISREG(st.st_mode);
}

static int dnet_listdir(void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr,	char *sub,
		unsigned char *first_id)
{
	int err = 0;
	DIR *dir;
	struct dirent *d;
	unsigned char id[DNET_ID_SIZE];
	unsigned int len;
	unsigned long long osize = 1024 * 1024, size;
	void *odata, *data;

	odata = malloc(osize);
	if (!odata) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	data = odata;
	size = osize;

	dir = opendir(sub);
	if (!dir) {
		err = -errno;
		goto err_out_free;
	}

	err = chdir(sub);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"Failed to change directory to '%s': %s.\n",
			sub, strerror(errno));
		goto err_out_close;
	}

	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

		if (dnet_is_regular(state, d->d_name) <= 0)
			continue;

		len = strlen(d->d_name);

		if (len != strlen(DNET_HISTORY_SUFFIX) + DNET_ID_SIZE*2)
			continue;

		if (strcmp(&d->d_name[DNET_ID_SIZE*2], DNET_HISTORY_SUFFIX))
			continue;

		dnet_convert_name_to_id(d->d_name, id);

		if (first_id) {
			err = dnet_id_cmp(first_id, id);
			if (err > 0)
				continue;
		}
		
		if (size < DNET_ID_SIZE) {
			err = dnet_send_reply(state, cmd, attr, odata, osize - size, 1);
			if (err)
				goto err_out_close;

			size = osize;
			data = odata;
		}

		memcpy(data, id, DNET_ID_SIZE);
		data += DNET_ID_SIZE;
		size -= DNET_ID_SIZE;

		dnet_command_handler_log(state, DNET_LOG_INFO,
			"%s -> %s.\n", d->d_name, dnet_dump_id(id));
	}

	if (osize != size) {
		err = dnet_send_reply(state, cmd, attr, odata, osize - size, 0);
		if (err)
			goto err_out_close;
	}

	err = chdir("..");
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"Failed to chdir to the parent: %s.\n", strerror(errno));
		goto err_out_close;
	}

	closedir(dir);
	free(odata);

	return 0;

err_out_close:
	closedir(dir);
err_out_free:
	free(odata);
err_out_exit:
	return err;
}

static int file_list(struct file_backend_root *r, void *state,
		struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	char sub[8];
	unsigned char start, last;
	int err;
	unsigned char id[DNET_ID_SIZE];

	err = dnet_state_get_range(state, cmd->id, id);
	if (err)
		return err;

	last = file_backend_get_dir(id, r->bit_mask) - 1;
	
	sprintf(sub, "%x", file_backend_get_dir(cmd->id, r->bit_mask));

	err = dnet_listdir(state, cmd, attr, sub, cmd->id);
	if (err && (err != -ENOENT))
		goto out_exit;

	err = 0;
	for (start = file_backend_get_dir(cmd->id, r->bit_mask) - 1; start != last; --start) {
		sprintf(sub, "%x", start);

		err = dnet_listdir(state, cmd, attr, sub, NULL);
		if (err && (err != -ENOENT))
			goto out_exit;
	}
	err = 0;

out_exit:
	return err;
}

static int dnet_update_history(struct file_backend_root *r, void *state,
		struct dnet_io_attr *io, int tmp)
{
	/* ff/$IDDNET_HISTORY_SUFFIX.tmp*/
	char history[DNET_ID_SIZE*2+1 + sizeof(DNET_HISTORY_SUFFIX) + 8 + 1 + 5];
	int fd, err;
	struct dnet_history_entry e;

	snprintf(history, sizeof(history), "%x/%s%s%s", file_backend_get_dir(io->origin, r->bit_mask),
			dnet_dump_id_len(io->origin, DNET_ID_SIZE),
			DNET_HISTORY_SUFFIX, (tmp)?".tmp":"");

	fd = open(history, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to open history file '%s': %s.\n",
				dnet_dump_id(io->origin), history, strerror(errno));
		goto err_out_exit;
	}

	dnet_setup_history_entry(&e, io->id, io->size, io->offset, 0);

	err = write(fd, &e, sizeof(struct dnet_history_entry));
	if (err <= 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to update history file '%s': %s.\n",
			dnet_dump_id(io->origin), history, strerror(errno));
		goto err_out_close;
	}

	if (r->sync)
		fsync(fd);
	close(fd);
	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int file_write(struct file_backend_root *r, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err, fd;
	char dir[8];
	struct dnet_io_attr *io = data;
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE;
	/* null byte + maximum directory length (32 bits in hex) +
	 * '/' directory prefix and optional history suffix */
	char file[DNET_ID_SIZE * 2 + 1 + 8 + 1 + sizeof(DNET_HISTORY_SUFFIX)];

	if (attr->size < sizeof(struct dnet_io_attr)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);

	data += sizeof(struct dnet_io_attr);

	snprintf(dir, sizeof(dir), "%x", file_backend_get_dir(io->origin, r->bit_mask));

	err = mkdir(dir, 0755);
	if (err < 0) {
		if (errno != EEXIST) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: faliled to create dir '%s': %s.\n",
					dnet_dump_id(cmd->id), dir, strerror(errno));
			goto err_out_exit;
		}
	}

	file_backend_setup_file(r, file, sizeof(file), io);

	if (io->flags & DNET_IO_FLAGS_APPEND)
		oflags |= O_APPEND;
	else
		oflags |= O_TRUNC;

	fd = open(file, oflags, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to open data file '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_exit;
	}

	if ((io->flags & DNET_IO_FLAGS_HISTORY) &&
			(io->size == sizeof(struct dnet_history_entry))) {
		struct dnet_history_entry e;
		struct dnet_history_entry *r = data;
		int sfd;

		sfd = open(file, oflags & ~O_APPEND, 0644);
		if (sfd < 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to reopen history file '%s': %s.\n",
					dnet_dump_id(io->origin), file, strerror(errno));
			goto err_out_close;
		}
		err = pread(sfd, &e, sizeof(struct dnet_history_entry), 0);
		if (err < 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to read history file '%s': %s.\n",
					dnet_dump_id(io->origin), file, strerror(errno));
			close(sfd);
			goto err_out_close;
		}

		if (err == 0) {
			dnet_setup_history_entry(&e, r->id, r->size + r->offset, 0, 0);
		} else {
			dnet_convert_history_entry(&e);
			dnet_convert_history_entry(r);
			if (e.size < r->offset + r->size)
				e.size = r->offset + r->size;
			dnet_convert_history_entry(r);
			dnet_convert_history_entry(&e);
		}

		err = pwrite(sfd, &e, sizeof(struct dnet_history_entry), 0);
		if (err <= 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to update metadata in history file '%s': %s.\n",
				dnet_dump_id(io->origin), file, strerror(errno));
			close(sfd);
			goto err_out_close;
		}
		close(sfd);
	}

	err = write(fd, data, io->size);
	if (err <= 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to write into '%s': %s.\n",
			dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_close;
	}

	if (r->sync)
		fsync(fd);
	close(fd);

	if (!(io->flags & DNET_IO_FLAGS_NO_HISTORY_UPDATE) &&
			!(io->flags & DNET_IO_FLAGS_HISTORY)) {
		err = dnet_update_history(r, state, io, 0);
		if (err) {
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to update history for '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
			goto err_out_exit;
		}
	}

	dnet_command_handler_log(state, DNET_LOG_NOTICE,
		"%s: IO file: '%s', offset: %llu, size: %llu.\n",
			dnet_dump_id(cmd->id), file,
			(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int file_read(struct file_backend_root *r, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	struct dnet_io_attr *io = data;
	int fd, err, deref = 0;
	size_t size;
	char file[DNET_ID_SIZE * 2 + 1 + 8 + 1 + sizeof(DNET_HISTORY_SUFFIX)];
	struct stat st;

	if (attr->size < sizeof(struct dnet_io_attr)) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	data += sizeof(struct dnet_io_attr);

	dnet_convert_io_attr(io);

	file_backend_setup_file(r, file, sizeof(file), io);

	fd = open(file, O_RDONLY, 0644);
	if (fd < 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to open data file '%s': %s.\n",
				dnet_dump_id(io->origin), file, strerror(errno));
		goto err_out_exit;
	}

	size = io->size;

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to stat file '%s': %s.\n",
				dnet_dump_id(io->origin), file, strerror(errno));
		goto err_out_close_fd;
	}

	size = dnet_backend_check_get_size(io, st.st_size);
	if (!size) {
		err = 0;
		goto err_out_close_fd;
	}

	if (attr->size == sizeof(struct dnet_io_attr)) {
		struct dnet_data_req *r;
		struct dnet_cmd *c;
		struct dnet_attr *a;
		struct dnet_io_attr *rio;

		r = dnet_req_alloc(state, sizeof(struct dnet_cmd) +
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		if (!r) {
			err = -ENOMEM;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to allocate reply attributes.\n",
					dnet_dump_id(io->origin));
			goto err_out_close_fd;
		}

		dnet_req_set_fd(r, fd, io->offset, size, 1);

		c = dnet_req_header(r);
		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		memcpy(c->id, io->origin, DNET_ID_SIZE);
		memcpy(rio->origin, io->origin, DNET_ID_SIZE);
	
		dnet_command_handler_log(state, DNET_LOG_NOTICE,
			"%s: read reply offset: %llu, size: %zu.\n",
				dnet_dump_id(io->origin),
				(unsigned long long)io->offset, size);

		if (cmd->flags & DNET_FLAGS_NEED_ACK)
			c->flags = DNET_FLAGS_MORE;

		c->status = 0;
		c->size = sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + size;
		c->trans = cmd->trans | DNET_TRANS_REPLY;

		a->cmd = DNET_CMD_READ;
		a->size = sizeof(struct dnet_io_attr) + size;
		a->flags = attr->flags;

		rio->size = size;
		rio->offset = io->offset;
		rio->flags = io->flags;

		dnet_convert_cmd(c);
		dnet_convert_attr(a);
		dnet_convert_io_attr(rio);

		err = dnet_data_ready(state, r);
		if (err)
			goto err_out_close_fd;

		deref = 1;
	} else {
		if (size > attr->size - sizeof(struct dnet_io_attr))
			size = attr->size - sizeof(struct dnet_io_attr);

		err = pread(fd, data, size, io->offset);
		if (err <= 0) {
			err = -errno;
			dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to read object data: %s.\n",
					dnet_dump_id(io->origin), strerror(errno));
			goto err_out_close_fd;
		}

		io->size = err;
		attr->size = sizeof(struct dnet_io_attr) + io->size;
	}
	if (!deref)
		close(fd);

	return 0;

err_out_close_fd:
	close(fd);
err_out_exit:
	return err;
}

static int file_del(struct file_backend_root *r, void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err = -EINVAL;
	struct dnet_io_attr *io;
	struct dnet_history_entry *e;
	int fd;
	struct stat st;
	char file[DNET_ID_SIZE * 2 + 8 + sizeof(DNET_HISTORY_SUFFIX)];
	unsigned long long num;

	if (!attr || !data)
		goto err_out_exit;

	if (attr->flags & DNET_ATTR_DIRECT_TRANSACTION) {
		snprintf(file, sizeof(file), "%x/%s", file_backend_get_dir(cmd->id, r->bit_mask),
			dnet_dump_id_len(cmd->id, DNET_ID_SIZE));
		remove(file);

		snprintf(file, sizeof(file), "%x/%s%s", file_backend_get_dir(cmd->id, r->bit_mask),
			dnet_dump_id_len(cmd->id, DNET_ID_SIZE), DNET_HISTORY_SUFFIX);
		remove(file);
		return 0;
	}

	if (attr->size != sizeof(struct dnet_io_attr))
		goto err_out_exit;

	io = data;
	dnet_convert_io_attr(io);

	snprintf(file, sizeof(file), "%x/%s%s", file_backend_get_dir(io->id, r->bit_mask),
			dnet_dump_id_len(io->id, DNET_ID_SIZE), DNET_HISTORY_SUFFIX);

	fd = open(file, O_RDWR);
	if (fd < 0) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to open to be deleted object '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to stat to be deleted object '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_close;
	}

	if (st.st_size % sizeof(struct dnet_history_entry)) {
		err = -EINVAL;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: corrupted history object '%s'.\n",
				dnet_dump_id(cmd->id), file);
		goto err_out_close;
	}

	e = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (e == MAP_FAILED) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to mmap to be deleted history object '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_close;
	}

	num = st.st_size / sizeof(struct dnet_history_entry);

	err = backend_del(state, io, e, num);
	if (err)
		goto err_out_unmap;

	err = ftruncate(fd, st.st_size - sizeof(struct dnet_history_entry));
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR,
				"%s: failed to truncate to be deleted history object '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
		goto err_out_unmap;
	}

	if (st.st_size == sizeof(struct dnet_history_entry)) {
		dnet_command_handler_log(state, DNET_LOG_INFO, "%s: unlinking history object '%s'.\n",
				dnet_dump_id(cmd->id), file);
		remove(file);

		snprintf(file, sizeof(file), "%x/%s", file_backend_get_dir(io->id, r->bit_mask),
				dnet_dump_id_len(io->id, DNET_ID_SIZE));
		remove(file);
	}

	munmap(e, st.st_size);
	close(fd);

	return 0;

err_out_unmap:
	munmap(e, st.st_size);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

int file_backend_command_handler(void *state, void *priv,
		struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	int err;
	struct file_backend_root *r = priv;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = file_write(r, state, cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = file_read(r, state, cmd, attr, data);
			break;
		case DNET_CMD_SYNC:
		case DNET_CMD_LIST:
			err = file_list(r, state, cmd, attr);
			break;
		case DNET_CMD_STAT:
			err = backend_stat(state, r->root, cmd, attr);
			break;
		case DNET_CMD_DEL:
			err = file_del(r, state, cmd, attr, data);
			break;
		default:
			err = -EINVAL;
			break;
	}

	return err;
}
