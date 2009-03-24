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

static int dnet_is_regular(char *path)
{
	struct stat st;
	int err;

	err = stat(path, &st);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to stat '%s' object: %s.\n", path, strerror(errno));
		return err;
	}

	return S_ISREG(st.st_mode);
}

static int dnet_send_list(void *state, struct dnet_cmd *cmd, void *data, unsigned int size)
{
	struct dnet_cmd c;
	struct dnet_attr a;

	c = *cmd;
	c.trans |= DNET_TRANS_REPLY;
	c.flags |= DNET_FLAGS_MORE;
	c.status = 0;
	c.size = sizeof(struct dnet_attr) + size;

	a.size = size;
	a.flags = 0;
	a.cmd = DNET_CMD_LIST;

	fprintf(stdout, "%s: sending %u list entries.\n", dnet_dump_id(cmd->id), size / DNET_ID_SIZE);

	return dnet_data_ready(state, &c, &a, data, size, 0, -1);
}

static int dnet_listdir(void *state, struct dnet_cmd *cmd,
		char *sub, unsigned char *first_id,
		void *data, unsigned int size)
{
	int err = 0;
	DIR *dir;
	struct dirent *d;
	unsigned char id[DNET_ID_SIZE];
	unsigned int len;
	unsigned int osize = size;
	void *odata = data;

	dir = opendir(sub);
	if (!dir) {
		err = -errno;
		return err;
	}

	err = chdir(sub);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to change directory to '%s': %s.\n", sub, strerror(errno));
		goto out_close;
	}

	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

		if (dnet_is_regular(d->d_name) <= 0)
			continue;

		len = strlen(d->d_name);

		if (len != strlen(DNET_HISTORY_SUFFIX) + DNET_ID_SIZE*2)
			continue;

		if (strcmp(&d->d_name[DNET_ID_SIZE*2], DNET_HISTORY_SUFFIX))
			continue;

		dnet_convert_name_to_id(d->d_name, id);

		if (first_id) {
			err = dnet_id_cmp(first_id, id);
			if (err >= 0)
				continue;
		}

		if (size >= DNET_ID_SIZE) {
			memcpy(data, id, DNET_ID_SIZE);
			data += DNET_ID_SIZE;
			size -= DNET_ID_SIZE;
		} else {
			err = dnet_send_list(state, cmd, odata, osize - size);
			if (err)
				goto out_close;

			size = osize;
			data = odata;
		}

		printf("%s -> %s.\n", d->d_name, dnet_dump_id(id));
	}

	if (osize != size) {
		err = dnet_send_list(state, cmd, odata, osize - size);
		if (err)
			goto out_close;
	}

	err = chdir("..");
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to chdir to the parent: %s.\n", strerror(errno));
	}

out_close:
	closedir(dir);

	return err;
}

static int dnet_cmd_list(void *state, struct dnet_cmd *cmd, struct dnet_attr *a __attribute__ ((unused)), void *data)
{
	char sub[3];
	unsigned char start;
	int err;
	unsigned long long size = 1024 * 1024;

	data = malloc(size);
	if (!data)
		return -ENOMEM;

	sprintf(sub, "%02x", cmd->id[0]);

	err = dnet_listdir(state, cmd, sub, cmd->id, data, size);
	if (err && (err != -ENOENT))
		goto out_exit;

	err = 0;
	if (cmd->id[0] != 0) {
		for (start = cmd->id[0]-1; start != 0; --start) {
			sprintf(sub, "%02x", start);

			err = dnet_listdir(state, cmd, sub, NULL, data, size);
			if (err && (err != -ENOENT))
				goto out_exit;
		}
		err = 0;
	}

out_exit:
	free(data);
	return err;
}

static int dnet_update_history(unsigned char *id, struct dnet_io_attr *io, int tmp)
{
	char history[DNET_ID_SIZE*2+1 + sizeof(DNET_HISTORY_SUFFIX) + 5 + 3]; /* ff/$IDDNET_HISTORY_SUFFIX.tmp*/
	int fd, err;

	snprintf(history, sizeof(history), "%02x/%s%s%s", id[0], dnet_dump_id(id), DNET_HISTORY_SUFFIX, (tmp)?".tmp":"");

	fd = open(history, O_RDWR | O_CREAT | O_APPEND | O_LARGEFILE, 0644);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "%s: failed to open history file '%s': %s.\n", dnet_dump_id(id), history, strerror(errno));
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);
	err = write(fd, io, sizeof(struct dnet_io_attr));
	dnet_convert_io_attr(io);

	if (err <= 0) {
		err = -errno;
		fprintf(stderr, "%s: failed to update history file '%s': %s.\n", dnet_dump_id(id), history, strerror(errno));
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

static int dnet_cmd_write(struct dnet_cmd *cmd,	struct dnet_attr *attr, void *data)
{
	int err;
	char dir[3];
	struct dnet_io_attr *io = data;
	int oflags = O_RDWR | O_CREAT | O_LARGEFILE;
	/* null byte + '%02x/' directory prefix and optional history suffix */
	char file[DNET_ID_SIZE * 2 + 1 + 3 + sizeof(DNET_HISTORY_SUFFIX)];

	if (attr->size <= sizeof(struct dnet_io_attr)) {
		fprintf(stderr, "%s: wrong write attribute, size does not match "
				"IO attribute size: size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
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
			fprintf(stderr, "%s: faliled to create dir '%s': %s.\n",
					dnet_dump_id(cmd->id), dir, strerror(errno));
			goto err_out_exit;
		}
	}

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		snprintf(file, sizeof(file), "%02x/%s%s", cmd->id[0], dnet_dump_id(cmd->id), DNET_HISTORY_SUFFIX);
	else
		snprintf(file, sizeof(file), "%02x/%s", cmd->id[0], dnet_dump_id(cmd->id));

	if (io->flags & DNET_IO_FLAGS_OBJECT) {
		int fd;

		if ((io->size != attr->size - sizeof(struct dnet_io_attr)) ||
				(io->size > cmd->size)){
			fprintf(stderr, "%s: wrong io size: %llu, must be equal to %llu.\n",
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
			fprintf(stderr, "%s: failed to open data file '%s': %s.\n",
					dnet_dump_id(cmd->id), file, strerror(errno));
			goto err_out_exit;
		}

		err = pwrite(fd, data, io->size, io->offset);
		if (err <= 0) {
			err = -errno;
			fprintf(stderr, "%s: failed to write into '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
			close(fd);
			goto err_out_exit;
		}

		fsync(fd);
		close(fd);
	}

	if ((io->flags & DNET_IO_FLAGS_HISTORY_UPDATE) && !(io->flags & DNET_IO_FLAGS_HISTORY)) {
		err = dnet_update_history(cmd->id, io, 0);
		if (err) {
			fprintf(stderr, "%s: failed to update history for '%s': %s.\n",
				dnet_dump_id(cmd->id), file, strerror(errno));
			goto err_out_exit;
		}
	}

	printf("%s: IO file: '%s', offset: %llu, size: %llu.\n",
			dnet_dump_id(cmd->id), file,
			(unsigned long long)io->offset, (unsigned long long)io->size);

	return 0;

err_out_exit:
	return err;
}

static int dnet_cmd_read(void *state, struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	struct dnet_io_attr *io = data;
	int fd, err;
	size_t size;
	/* null byte + '%02x/' directory prefix + history suffix */
	char file[DNET_ID_SIZE * 2 + 1 + 3 + sizeof(DNET_HISTORY_SUFFIX)];
	struct dnet_cmd *c;
	struct dnet_attr *a;
	struct dnet_io_attr *rio;
	off_t offset;
	size_t total_size;

	if (attr->size < sizeof(struct dnet_io_attr)) {
		fprintf(stderr, "%s: wrong read attribute, size does not match "
				"IO attribute size: size: %llu, must be: %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)attr->size,
				sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	dnet_convert_io_attr(io);

	if (io->flags & DNET_IO_FLAGS_HISTORY)
		snprintf(file, sizeof(file), "%02x/%s%s", io->id[0], dnet_dump_id(io->id),
				DNET_HISTORY_SUFFIX);
	else
		snprintf(file, sizeof(file), "%02x/%s", io->id[0], dnet_dump_id(io->id));

	fd = open(file, O_RDONLY, 0644);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "%s: failed to open data file '%s': %s.\n",
				dnet_dump_id(io->id), file, strerror(errno));
		goto err_out_exit;
	}

	size = io->size;
	if ((io->size == 0) && (attr->size == sizeof(struct dnet_io_attr))) {
		struct stat st;

		err = fstat(fd, &st);
		if (err) {
			err = -errno;
			fprintf(stderr, "%s: failed to stat file '%s': %s.\n",
					dnet_dump_id(io->id), file, strerror(errno));
			goto err_out_close_fd;
		}

		size = st.st_size;
	}
	
	if (attr->size == sizeof(struct dnet_io_attr)) {
		c = malloc(sizeof(struct dnet_cmd) + sizeof(struct dnet_attr) +
				sizeof(struct dnet_io_attr));
		if (!c) {
			err = -ENOMEM;
			fprintf(stderr, "%s: failed to allocate reply attributes.\n",
					dnet_dump_id(io->id));
			goto err_out_close_fd;
		}

		a = (struct dnet_attr *)(c + 1);
		rio = (struct dnet_io_attr *)(a + 1);

		total_size = size;
		offset = io->offset;

		memcpy(c->id, io->id, DNET_ID_SIZE);
		memcpy(rio->id, io->id, DNET_ID_SIZE);

		while (total_size) {
			size = total_size;
			if (size > DNET_MAX_READ_TRANS_SIZE)
				size = DNET_MAX_READ_TRANS_SIZE;

			printf("%s: read reply offset: %llu, size: %zu, c: %p.\n",
					dnet_dump_id(io->id),
					(unsigned long long)offset, size, c);

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

			rio->size = size;
			rio->offset = offset;
			rio->flags = io->flags;

			dnet_convert_io_attr(rio);

			err = dnet_data_ready(state, c, a,
				rio, sizeof(struct dnet_io_attr),
				offset, fd);
			if (err) {
				fprintf(stderr, "%s: failed to send read reply.\n",
						dnet_dump_id(io->id));
				goto err_out_free;
			}

			offset += size;
			total_size -= size;
		}

		free(c);
	} else {
		size = attr->size - sizeof(struct dnet_io_attr);
		data += sizeof(struct dnet_io_attr);

		err = pread(fd, data, size, io->offset);
		if (err <= 0) {
			err = -errno;
			fprintf(stderr, "%s: failed to read object data: %s.\n",
					dnet_dump_id(cmd->id), strerror(errno));
			goto err_out_close_fd;
		}

		io->size = err;
		attr->size = sizeof(struct dnet_io_attr) + err;
	}
	close(fd);

	return 0;

err_out_free:
	free(c);
err_out_close_fd:
	close(fd);
err_out_exit:
	return err;
}

static int dnet_cmd_exec(void *state __attribute__ ((unused)), struct dnet_cmd *cmd, struct dnet_attr *attr, void *data)
{
	char *command = data;
	pid_t pid;
	int err;

	if (!attr->size)
		return 0;

	printf("%s: command: '%s'.\n", dnet_dump_id(cmd->id), command);

	pid = fork();
	if (pid < 0) {
		err = -errno;
		fprintf(stderr, "%s: failed to fork a child process", dnet_dump_id(cmd->id));
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
			fprintf(stderr, "%s: failed to wait for child (%d) process: %s.\n",
					dnet_dump_id(cmd->id), (int)pid, strerror(errno));
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

int file_backend_command_handler(void *state, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *data)
{
	int err;

	switch (attr->cmd) {
		case DNET_CMD_WRITE:
			err = dnet_cmd_write(cmd, attr, data);
			break;
		case DNET_CMD_READ:
			err = dnet_cmd_read(state, cmd, attr, data);
			break;
		case DNET_CMD_LIST:
			err = dnet_cmd_list(state, cmd, attr, data);
			break;
		case DNET_CMD_EXEC:
			err = dnet_cmd_exec(state, cmd, attr, data);
			break;
		default:
			err = -EPROTO;
			break;
	}

	return err;
}
