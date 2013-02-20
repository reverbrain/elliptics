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
static int backend_vm_stat(struct dnet_stat *st)
{
	int err;
	FILE *f;
	float la[3];
	unsigned long long stub;

	f = fopen("/proc/loadavg", "r");
	if (!f) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to open '/proc/loadavg': %s [%d].\n",
				strerror(errno), errno);
		goto err_out_exit;
	}

	err = fscanf(f, "%f %f %f", &la[0], &la[1], &la[2]);
	if (err != 3) {
		err = -errno;
		if (!err)
			err = -EINVAL;

		dnet_backend_log(DNET_LOG_ERROR, "Failed to read load average data: %s [%d].\n",
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
		dnet_backend_log(DNET_LOG_ERROR, "Failed to open '/proc/meminfo': %s [%d].\n",
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

static int backend_vm_stat(struct dnet_stat *st)
{
	int err;
	struct loadavg la;
	long page_size = 0;
	size_t sz = sizeof(la);

	err = sysctlbyname("vm.loadavg", &la, &sz, NULL, 0);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to get load average data: %s [%d].\n",
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
static int backend_vm_stat(struct dnet_stat *st __unused)
{
	return 0;
}
#endif

int backend_stat_low_level(const char *path, struct dnet_stat *st)
{
	struct statvfs s;
	int err;
	float la[3];

	err = statvfs(path, &s);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to get VFS statistics of '%s': %s [%d].\n",
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

	err = backend_vm_stat(st);
	if (err)
		return err;

	la[0] = (float)st->la[0] / 100.0;
	la[1] = (float)st->la[1] / 100.0;
	la[2] = (float)st->la[2] / 100.0;

	dnet_backend_log(DNET_LOG_DEBUG, "Stat: la: %f %f %f, mem: total: %llu, free: %llu, cache: %llu.\n",
		la[0], la[1], la[2],
		(unsigned long long)st->vm_total, (unsigned long long)st->vm_free, (unsigned long long)st->vm_cached);

	dnet_convert_stat(st);

	return 0;
}

int backend_stat(void *state, char *path, struct dnet_cmd *cmd)
{
	struct dnet_stat st;
	int err;

	if (!path)
		path = ".";

	memset(&st, 0, sizeof(struct dnet_stat));

	err = backend_stat_low_level(path, &st);
	if (err)
		return err;

	return dnet_send_reply(state, cmd, &st, sizeof(struct dnet_stat), 0);
}

int backend_storage_size(struct dnet_config_backend *b, const char *root)
{
	struct statvfs s;
	int err;

	err = statvfs(root, &s);
	if (err) {
		err = -errno;
		dnet_backend_log(DNET_LOG_ERROR, "Failed to get VFS statistics of '%s': %s [%d].\n",
				root, strerror(errno), errno);
		return err;
	}

	b->storage_size = s.f_frsize * s.f_blocks;
	b->storage_free = s.f_bsize * s.f_bavail;

	return 0;
}

/*
 * Extensions stuff
 */

/*!
 * Initialize allocated extension list
 */
void dnet_ext_list_init(struct dnet_ext_list *elist)
{
	if (elist == NULL)
		return;
	memset(elist, 0, sizeof(struct dnet_ext_list));
}

/*!
 * Allocates and returns new extension list
 */
struct dnet_ext_list *dnet_ext_list_create()
{
	return calloc(1, sizeof(struct dnet_ext_list));
}

/*!
 * Destroy extension list
 */
void dnet_ext_list_destroy(struct dnet_ext_list *elist)
{
	/* TODO: Recursively destroy all extensions */
}

/*!
 * Extracts \a elist from \a datap, replaces \a datap pointer and adjusts \a
 * sizep. In case \a free_data is set then data pointed by \a *datap is free'd.
 * TODO: Endian conversions.
 */
int dnet_ext_list_extract(void **datap, uint64_t *sizep,
		struct dnet_ext_list *elist, int free_data)
{
	struct dnet_ext_list_hdr *hdr;	/* Extensions header */
	uint64_t new_size;		/* Size of data without extensions */
	void *new_data;			/* Data without extensions */
	/* Shortcut */
	static const size_t hdr_size = sizeof(struct dnet_ext_list_hdr);

	/* Parameter checks */
	if (datap == NULL || *datap == NULL)
		return -EINVAL;
	if (sizep == NULL || elist == NULL)
		return -EINVAL;

	/* Sanity checks */
	if (*sizep < hdr_size)
		return -ERANGE;

	/*
	 * Shortcut
	 *
	 * TODO: For now we account only for headers size, but when we
	 * support additional extensions we should account for
	 * hdr_size + hdr->size
	 */
	new_size = *sizep - hdr_size;
	hdr = (struct dnet_ext_list_hdr *)*datap;

	/* Extract payload from \a datap */
	if ((new_data = malloc(new_size)) == NULL)
		return -ENOMEM;
	memcpy(new_data, (unsigned char *)*datap + hdr_size, new_size);

	/* Extract header */
	memset(elist, 0, sizeof(struct dnet_ext_list));
	elist->timestamp = hdr->timestamp;
	elist->count = hdr->count;
	elist->size = hdr->size;

	/*
	 * Currently we do not support any extensions beyond header itself
	 * so assert on any extensions.
	 *
	 * TODO: Extract all extensions
	 */
	if (elist->size != 0 || elist->count != 0) {
		free(new_data);
		return -ENOTSUP;
	}

	/* Free old data */
	if (free_data != 0)
		free(*datap);

	/* Swap data, adjust size */
	*datap = new_data;
	*sizep = new_size;

	return 0;
}

/*!
 * Combines \a datap with \a elist and fixes \a sizep
 *
 * NB! It does not free memory pointed by \a datap
 * TODO: Endian conversions.
 */
int dnet_ext_list_combine(void **datap, uint64_t *sizep,
		const struct dnet_ext_list *elist)
{
	struct dnet_ext_list_hdr *hdr;	/* Extensions header */
	uint64_t new_size;		/* Size of data without extensions */
	void *new_data;			/* Data without extensions */
	/* Shortcut */
	static const size_t hdr_size = sizeof(struct dnet_ext_list_hdr);

	/* Parameter checks */
	if (datap == NULL || *datap == NULL)
		return -EINVAL;
	if (sizep == NULL || elist == NULL)
		return -EINVAL;

	/*
	 * Shortcut
	 *
	 * TODO: For now we account only for headers size, but when we
	 * support additional extensions we should account for
	 * hdr_size + hdr->size
	 */
	new_size = *sizep + hdr_size;

	/* Extract data, copy it, swap it, adjust size */
	if ((new_data = malloc(new_size)) == NULL)
		return -ENOMEM;
	memcpy((unsigned char *)new_data + hdr_size, *datap, *sizep);

	hdr = (struct dnet_ext_list_hdr *)new_data;
	memset(hdr, 0, sizeof(struct dnet_ext_list_hdr));
	hdr->size = elist->size;
	hdr->count = elist->count;
	hdr->timestamp = elist->timestamp;

	/*
	 * Currently we do not support any extensions beyond header itself
	 * so assert on any extensions.
	 *
	 * TODO: Combine all extensions
	 */
	if (elist->size != 0 || elist->count != 0) {
		free(new_data);
		return -ENOTSUP;
	}

	*datap = new_data;
	*sizep = new_size;

	return 0;
}
