/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _XOPEN_SOURCE 600

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

#include "elliptics/core.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "elliptics/backends.h"
#include "../library/elliptics.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

int backend_storage_size(struct dnet_config_backend *b, const char *root)
{
	struct statvfs s;
	int err;

	err = statvfs(root, &s);
	if (err) {
		err = -errno;
		dnet_backend_log(b->log, DNET_LOG_ERROR, "Failed to get VFS statistics of '%s': %s [%d].",
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
	elist->version = DNET_EXT_VERSION_V1;
}

/*!
 * Destroy extension list
 */
void dnet_ext_list_destroy(struct dnet_ext_list *elist)
{
	free(elist->data);
}

/*!
 * Reads extension header from given fd and offset
 */
int dnet_ext_hdr_read(struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset)
{
	int err;

	if (ehdr == NULL || fd < 0)
		return -EINVAL;

	err = pread(fd, ehdr, sizeof(struct dnet_ext_list_hdr), offset);
	if (err != sizeof(struct dnet_ext_list_hdr))
		return (err == -1) ? -errno : -EINTR;
	return 0;
}

/*!
 * Reads extension header from given fd and offset
 */
int dnet_ext_hdr_write(const struct dnet_ext_list_hdr *ehdr, int fd, uint64_t offset)
{
	int err;

	if (ehdr == NULL || fd < 0)
		return -EINVAL;

	err = pwrite(fd, ehdr, sizeof(struct dnet_ext_list_hdr), offset);
	if (err != sizeof(struct dnet_ext_list_hdr))
		return (err == -1) ? -errno : -EINTR;
	return 0;
}

/*!
 * Converts representation from host-independed on-disk to host-depended
 * in-memory.
 */
int dnet_ext_hdr_to_list(const struct dnet_ext_list_hdr *ehdr,
		struct dnet_ext_list *elist)
{
	if (ehdr == NULL || elist == NULL)
		return -EINVAL;

	memset(elist, 0, sizeof(struct dnet_ext_list));
	elist->version = ehdr->version;
	elist->timestamp.tsec = dnet_bswap64(ehdr->timestamp.tsec);
	elist->timestamp.tnsec = dnet_bswap64(ehdr->timestamp.tnsec);
	elist->size = dnet_bswap32(ehdr->size);
	elist->flags = dnet_bswap64(ehdr->flags);

	return 0;
}

/*!
 * Converts representation from host-depended in-memory to host-independed
 * on-disk.
 */
int dnet_ext_list_to_hdr(const struct dnet_ext_list *elist,
		struct dnet_ext_list_hdr *ehdr)
{
	if (ehdr == NULL || elist == NULL)
		return -EINVAL;

	memset(ehdr, 0, sizeof(struct dnet_ext_list_hdr));
	ehdr->version = elist->version;
	ehdr->size = dnet_bswap32(elist->size);
	ehdr->flags = dnet_bswap64(elist->flags);
	ehdr->timestamp.tsec = dnet_bswap64(elist->timestamp.tsec);
	ehdr->timestamp.tnsec = dnet_bswap64(elist->timestamp.tnsec);

	return 0;
}

/*!
 * Fills needed fields in \a io with data from given \a elist
 */
int dnet_ext_list_to_io(const struct dnet_ext_list *elist, struct dnet_io_attr *io)
{
	if (elist == NULL || io == NULL)
		return -EINVAL;

	io->timestamp = elist->timestamp;
	io->user_flags = elist->flags;

	return 0;
}

/*!
 * Fills needed fields in \a elist with data from given \a io
 */
int dnet_ext_io_to_list(const struct dnet_io_attr *io, struct dnet_ext_list *elist)
{
	if (elist == NULL || io == NULL)
		return -EINVAL;

	elist->timestamp = io->timestamp;
	elist->flags = io->user_flags;

	return 0;
}

/*!
 * Extracts \a elist from \a datap, replaces \a datap pointer and adjusts \a
 * sizep. In case \a free_data is set then data pointed by \a *datap is free'd.
 */
int dnet_ext_list_extract(void **datap, uint64_t *sizep,
		struct dnet_ext_list *elist, enum dnet_ext_free_data free_data)
{
	struct dnet_ext_list_hdr *hdr;	/* Extensions header */
	uint64_t new_size;		/* Size of data without extensions */
	void *new_data;			/* Data without extensions */
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
	 * TODO: For now we account only for header size, but when we add
	 * support additional extensions we should account for hdr_size +
	 * hdr->size
	 */
	new_size = *sizep - hdr_size;
	hdr = (struct dnet_ext_list_hdr *)*datap;

	/* Extract payload from \a datap */
	new_data = (unsigned char *)*datap + hdr_size;
	dnet_ext_hdr_to_list(hdr, elist);

	/*
	 * Currently we do not support any extensions beyond header itself
	 * so assert on any extensions.
	 *
	 * TODO: Extract all extensions
	 */
	if (elist->size != 0)
		return -ENOTSUP;
	if (elist->version <= DNET_EXT_VERSION_FIRST
			|| elist->version >= DNET_EXT_VERSION_LAST)
		return -ENOTSUP;

	/* Save original pointer to data */
	if (free_data == DNET_EXT_FREE_ON_DESTROY)
		elist->data = *datap;

	/* Swap data, adjust size */
	*datap = new_data;
	*sizep = new_size;

	return 0;
}

/*!
 * Combines \a datap with \a elist and fixes \a sizep
 * NB! It does not free memory pointed by \a datap
 *
 * XXX: It does heavy weight malloc+memcpy. This can be avoided if either
 * provided data buffer was prepended with empty space or backend supported
 * writev(2)-like interface.
 */
int dnet_ext_list_combine(void **datap, uint64_t *sizep,
		const struct dnet_ext_list *elist)
{
	struct dnet_ext_list_hdr *hdr;	/* Extensions header */
	uint64_t new_size;		/* Size of data without extensions */
	void *new_data;			/* Data without extensions */
	static const size_t hdr_size = sizeof(struct dnet_ext_list_hdr);

	/* Parameter checks */
	if (datap == NULL || *datap == NULL)
		return -EINVAL;
	if (sizep == NULL || elist == NULL)
		return -EINVAL;

	/*
	 * Shortcut
	 *
	 * TODO: For now we account only for header size, but when we add
	 * support additional extensions we should account for hdr_size +
	 * hdr->size
	 */
	new_size = *sizep + hdr_size;

	/* Allocate space, copy data, prepend header */
	if ((new_data = malloc(new_size)) == NULL)
		return -ENOMEM;
	memcpy((unsigned char *)new_data + hdr_size, *datap, *sizep);

	hdr = (struct dnet_ext_list_hdr *)new_data;
	dnet_ext_list_to_hdr(elist, hdr);

	/*
	 * Currently we do not support any extensions beyond header itself
	 * so assert on any extensions.
	 *
	 * TODO: Combine all extensions
	 */
	if (elist->size != 0) {
		free(new_data);
		return -ENOTSUP;
	}
	if (elist->version <= DNET_EXT_VERSION_FIRST
			|| elist->version >= DNET_EXT_VERSION_LAST) {
		free(new_data);
		return -ENOTSUP;
	}

	/* Swap data, adjust size */
	*datap = new_data;
	*sizep = new_size;

	return 0;
}
