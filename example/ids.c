/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <sys/stat.h>
#include <sys/statvfs.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "elliptics/interface.h"

static void ids_usage(char *p)
{
	fprintf(stderr, "Usage: %s <options>\n"
			"  -i file                   - ids file\n"
			"  -r file                   - random file\n"
			"  -d dir                    - storage dir path\n"
			"  -t                        - use total size of the storage device instead of free size\n"
			"  -h                        - this help\n"
			, p);
	exit(-1);
}

static int ids_append(char *random_file, int fd, unsigned long long diff)
{
	unsigned long long sz = 1024 * 1024;
	void *buf;
	int err, rnd;

	rnd = open(random_file, O_RDONLY);
	if (rnd == -1) {
		err = -errno;
		fprintf(stderr, "Failed to open random file '%s': %s [%d]\n",
				random_file, strerror(errno), errno);
		goto err_out_exit;
	}

	buf = malloc(sz);
	if (!buf) {
		err = -ENOMEM;
		goto err_out_close;
	}

	while (diff != 0) {
		if (sz > diff)
			sz = diff;

		err = read(rnd, buf, sz);
		if (err <= 0) {
			fprintf(stderr, "Failed to read from random file '%s': %s [%d]\n",
				random_file, strerror(errno), errno);
			goto err_out_free;
		}

		err = write(fd, buf, err);
		if (err <= 0) {
			fprintf(stderr, "Failed to write into ids file: %s [%d]\n",
				strerror(errno), errno);
			goto err_out_free;
		}

		diff -= err;
	}
	err = 0;

err_out_free:
	free(buf);
err_out_close:
	close(fd);
err_out_exit:
	return err;
}

static int ids_update(char *ids_file, char *random_file, unsigned long long new_size)
{
	struct stat st;
	int fd, err;
	unsigned long long new_num, old_num;

	fd = open(ids_file, O_RDWR | O_CREAT | O_APPEND, 0644);
	if (fd == -1) {
		err = -errno;
		fprintf(stderr, "Faield to open ids file '%s': %s [%d]\n",
				ids_file, strerror(errno), errno);
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err == -1) {
		err = -errno;
		fprintf(stderr, "Faield to stat ids file '%s': %s [%d]\n",
				ids_file, strerror(errno), errno);
		goto err_out_close;
	}

	old_num = st.st_size / DNET_ID_SIZE;
	new_num = new_size / (100 * 1024 * 1024 * 1024ULL) + 1;

	if (new_num < old_num) {
		err = ftruncate(fd, new_num * DNET_ID_SIZE);
		if (err == -1) {
			err = -errno;
			fprintf(stderr, "Faield to truncate ids file '%s': %llu -> %llu (in IDs, not bytes): %s [%d]\n",
				ids_file, old_num, new_num, strerror(errno), errno);
			goto err_out_close;
		}
	} else {
		err = ids_append(random_file, fd, (new_num - old_num) * DNET_ID_SIZE);
		if (err)
			goto err_out_close;
	}
	err = 0;

	fprintf(stderr, "Updated '%s': %llu -> %llu (in IDs, not bytes)\n",
			ids_file, old_num, new_num);

err_out_close:
	close(fd);
err_out_exit:
	return err;
}

int main(int argc, char *argv[])
{
	int ch, err;
	struct statvfs s;
	char *random = "/dev/urandom";
	char *ids = NULL;
	char *dir = NULL;
	int total = 0;
	unsigned long long storage_size;

	while ((ch = getopt(argc, argv, "i:r:d:th")) != -1) {
		switch (ch) {
			case 'i':
				ids = optarg;
				break;
			case 'r':
				random = optarg;
				break;
			case 'd':
				dir = optarg;
				break;
			case 't':
				total = 1;
				break;
			case 'h':
			default:
				ids_usage(argv[0]);
				/* not reached */
		}
	}

	if (!ids || !dir) {
		fprintf(stderr, "Both ids and dir options must be specified\n");
		ids_usage(argv[0]);
		/* not reached */
	}

	err = statvfs(dir, &s);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to get VFS statistics of '%s': %s [%d].\n",
				dir, strerror(errno), errno);
		return err;
	}

	if (total)
		storage_size = s.f_frsize * s.f_blocks;
	else
		storage_size = s.f_bsize * s.f_bavail;

	return ids_update(ids, random, storage_size);
}
