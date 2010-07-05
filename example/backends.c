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
#include <sys/statvfs.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "backends.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#if defined HAVE_PROC_STAT
static int backend_vm_stat(void *state, struct dnet_stat *st)
{
	int err;
	FILE *f;
	float la[3];
	unsigned long long stub;

	f = fopen("/proc/loadavg", "r");
	if (!f) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR, "Failed to open '/proc/loadavg': %s [%d].\n",
				strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%f %f %f", &la[0], &la[1], &la[2]);
	if (err != 3) {
		err = -errno;
		if (!err)
			err = -EINVAL;

		dnet_command_handler_log(state, DNET_LOG_ERROR, "Failed to read load average data: %s [%d].\n",
				strerror(errno), errno);
		goto err_out_close;
	}

	st->la[0] = la[0] * 100;
	st->la[1] = la[1] * 100;
	st->la[2] = la[2] * 100;

	fclose(f);

	f = fopen("/proc/meminfo", "r");
	if (!f) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR, "Failed to open '/proc/meminfo': %s [%d].\n",
				strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "MemTotal:%llu kB\n", (unsigned long long *)&st->vm_total);
	err = fscanf(f, "MemFree:%llu kB\n", (unsigned long long *)&st->vm_free);
	err = fscanf(f, "Buffers:%llu kB\n", (unsigned long long *)&st->vm_buffers);
	err = fscanf(f, "Cached:%llu kB\n", (unsigned long long *)&st->vm_cached);
	err = fscanf(f, "SwapCached:%llu kB\n", (unsigned long long *)&stub);
	err = fscanf(f, "Active:%llu kB\n", (unsigned long long *)&st->vm_active);
	err = fscanf(f, "Inactive:%llu kB\n", (unsigned long long *)&st->vm_inactive);

	fclose(f);
	return 0;

err_out_close:
	fclose(f);
err_out_exit:
	return err;
}
#elif defined HAVE_SYSCTL_STAT
#include <sys/sysctl.h>
#include <sys/resource.h>

static int backend_vm_stat(void *state, struct dnet_stat *st)
{
	int err;
	struct loadavg la;
	long page_size = 0;
	size_t sz = sizeof(la);

	err = sysctlbyname("vm.loadavg", &la, &sz, NULL, 0);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR, "Failed to get load average data: %s [%d].\n",
				strerror(errno), errno);
		return err;
	}

	st->la[0] = (double)la.ldavg[0] / la.fscale * 100;
	st->la[1] = (double)la.ldavg[1] / la.fscale * 100;
	st->la[2] = (double)la.ldavg[2] / la.fscale * 100;

	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_active_count", &st->vm_active, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_inactive_count", &st->vm_inactive, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_cache_count", &st->vm_cached, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_free_count", &st->vm_free, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_wire_count", &st->vm_buffers, &sz, NULL, 0);
	sz = sizeof(uint64_t);
	sysctlbyname("vm.stats.vm.v_page_count", &st->vm_total, &sz, NULL, 0);
	sz = sizeof(page_size);
	sysctlbyname("vm.stats.vm.v_page_size", &page_size, &sz, NULL, 0);

	page_size /= 1024;

	st->vm_total *= page_size;
	st->vm_active *= page_size;
	st->vm_inactive *= page_size;
	st->vm_free *= page_size;
	st->vm_cached *= page_size;
	st->vm_buffers *= page_size;

	return 0;
}
#else
static int backend_vm_stat(void *state __unused, struct dnet_stat *st __unused)
{
	return 0;
}
#endif

static int backend_stat_low_level(void *state, const char *path, struct dnet_stat *st)
{
	struct statvfs s;
	int err;
	float la[3];

	err = statvfs(path, &s);
	if (err) {
		err = -errno;
		dnet_command_handler_log(state, DNET_LOG_ERROR, "Failed to get VFS statistics of '%s': %s [%d].\n",
				path, strerror(errno), errno);
		return err;
	}

	st->bsize = s.f_bsize;
	st->frsize = s.f_frsize;
	st->blocks = s.f_blocks;
	st->bfree = s.f_bfree;
	st->bavail = s.f_bavail;
	st->files = s.f_files;
	st->ffree = s.f_ffree;
	st->favail = s.f_favail;
	st->fsid = s.f_fsid;
	st->flag = s.f_flag;
	st->namemax = s.f_namemax;

	err = backend_vm_stat(state, st);
	if (err)
		return err;

	la[0] = (float)st->la[0] / 100.0;
	la[1] = (float)st->la[1] / 100.0;
	la[2] = (float)st->la[2] / 100.0;

	dnet_command_handler_log(state, DNET_LOG_INFO, "Stat: la: %f %f %f, mem: total: %llu, free: %llu, cache: %llu.\n",
		la[0], la[1], la[2],
		(unsigned long long)st->vm_total, (unsigned long long)st->vm_free, (unsigned long long)st->vm_cached);

	dnet_convert_stat(st);

	return 0;
}

int backend_stat(void *state, char *path, struct dnet_cmd *cmd, struct dnet_attr *attr)
{
	struct dnet_stat st;
	int err;

	if (!path)
		path = ".";

	memset(&st, 0, sizeof(struct dnet_stat));

	err = backend_stat_low_level(state, path, &st);
	if (err)
		return err;

	return dnet_send_reply(state, cmd, attr, &st, sizeof(struct dnet_stat), 0);
}

int backend_del(void *state, struct dnet_io_attr *io, struct dnet_history_entry *e, unsigned int num)
{
	unsigned int i;

	for (i=1; i<num; ++i) {
		if (!memcmp(io->origin, e[i].id, DNET_ID_SIZE))
			break;
	}

	if (i == num) {
		if (memcmp(io->origin, e[0].id, DNET_ID_SIZE)) {

			dnet_command_handler_log(state, DNET_LOG_INFO,
				"%s: requested transaction was not found.\n",
				dnet_dump_id(io->origin));
			return -ENOENT;
		}
	}

	dnet_command_handler_log(state, DNET_LOG_INFO,
			"%s: removing transaction from position %u/%u.\n",
			dnet_dump_id(io->id), i, num);

	if (i < num - 1)
		memmove(&e[i], &e[i+1], (num - i - 1) * sizeof(struct dnet_history_entry));

	return 0;
}


static int backend_write_history_process(void *state, void *backend, struct dnet_io_attr *io,
					struct dnet_meta *m, void *data,
		int (* process)(void *state, void *backend, struct dnet_io_attr *io,
					struct dnet_meta *m, void *data))
{
	int err;
	uint32_t old_size = m->size;

	err = process(state, backend, io, m, data);

	dnet_command_handler_log(state, DNET_LOG_INFO, "%s: history update: type: %d, "
			"size: %u -> %u: %d\n",
			dnet_dump_id(io->id), m->type, old_size, m->size, err);
	return err;
}

int backend_write_history(void *state, void *backend, struct dnet_io_attr *io, void *iodata,
		int (* process)(void *state, void *backend, struct dnet_io_attr *io,
					struct dnet_meta *m, void *data))
{
	int err = 0;

	if (io->flags & DNET_IO_FLAGS_META) {
		struct dnet_meta *meta = (struct dnet_meta *)iodata;

		while (io->size) {
			dnet_convert_meta(meta);

			if (io->size < sizeof(struct dnet_meta) + meta->size) {
				dnet_command_handler_log(state, DNET_LOG_ERROR,
						"%s: history update failed: meta size "
						"(%u plus meta structure size) is more than "
						"io size (%llu).\n",
					dnet_dump_id(io->id), meta->size,
					(unsigned long long)io->size);
				err = -EINVAL;
				goto err_out_exit;
			}

			err = backend_write_history_process(state, backend, io,
					meta, meta->data, process);
			if (err)
				goto err_out_exit;

			io->size -= meta->size + sizeof(struct dnet_meta);
			meta = (struct dnet_meta *)(meta->data + meta->size);
		}
	} else {
		struct dnet_meta m;

		memset(&m, 0, sizeof(struct dnet_meta));
		m.type = DNET_META_HISTORY;
		m.size = io->size;

		err = backend_write_history_process(state, backend, io, &m, iodata, process);
		if (err)
			goto err_out_exit;
	}

err_out_exit:
	return err;
}

void *backend_process_meta(void *state, struct dnet_io_attr *io, void *hdata, uint32_t *size,
		struct dnet_meta *m, void *data)
{
	struct dnet_node *n = dnet_get_node_from_state(state);
	void *allocated = NULL;
	void *tmp = data;

	if (io->flags & DNET_IO_FLAGS_APPEND) {
		struct dnet_meta *meta;

		meta = dnet_meta_search(n, hdata, *size, m->type);
		if (meta) {
			struct dnet_meta converted = *meta;

			dnet_convert_meta(&converted);
			tmp = allocated = malloc(converted.size + m->size);
			if (!tmp) {
				hdata = NULL;
				goto err_out_exit;
			}

			memcpy(tmp, meta->data, converted.size);
			memcpy(tmp + converted.size, data, m->size);

			m->size += converted.size;
		}
	}

	hdata = dnet_meta_replace(n, hdata, size, m, tmp);
	if (!hdata) {
		dnet_command_handler_log(state, DNET_LOG_ERROR,
			"%s: failed to replace metadata.\n",
				dnet_dump_id(io->id));
		goto err_out_exit;
	}

err_out_exit:
	free(allocated);
	return hdata;
}
