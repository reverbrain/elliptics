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

#ifndef __DNET_CORE_H
#define __DNET_CORE_H

#include <elliptics/typedefs.h>

#define DNET_HISTORY_SUFFIX	".history"
#define DNET_META_SUFFIX	"\0meta"

#ifdef CONFIG_ID_SIZE
#define DNET_ID_SIZE		CONFIG_ID_SIZE
#else
#define DNET_ID_SIZE		64
#endif
#define DNET_MAX_NAME_LEN	64

/*
 * Each read transaction reply is being split into
 * chunks of this bytes max, thus reading transaction
 * callback will be invoked multiple times.
 */
#define DNET_MAX_TRANS_SIZE	(1024*1024*10)

/*
 * When IO request is less than this constant,
 * system copies data into contiguous block with headers
 * and sends it using single syscall.
 */
#define DNET_COPY_IO_SIZE	512

#ifndef HAVE_LARGEFILE_SUPPORT
#define O_LARGEFILE		0
#endif

#ifdef __GNUC__
#define DNET_LOG_CHECK  __attribute__ ((format(printf, 3, 4)))
#else
#define DNET_LOG_CHECK
#endif

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))

/*
 * Default notify hash table size.
 */
#define DNET_DEFAULT_NOTIFY_HASH_SIZE	256

/*
 * Default check timeout in seconds.
 */
#define DNET_DEFAULT_CHECK_TIMEOUT_SEC	60

#define DNET_DEFAULT_STALL_TRANSACTIONS 5

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/* checksum size, must be enough to store sha512 hash */
#define DNET_CSUM_SIZE		64

#endif /* __DNET_CORE_H */
