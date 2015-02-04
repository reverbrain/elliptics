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

#ifndef __DNET_CORE_H
#define __DNET_CORE_H

#define DNET_HISTORY_SUFFIX	".history"
#define DNET_META_SUFFIX	"\0meta"

#ifdef CONFIG_ID_SIZE
#define DNET_ID_SIZE		CONFIG_ID_SIZE
#else
#define DNET_ID_SIZE		64
#endif
#define DNET_MAX_NAME_LEN	64
#define DNET_ID_STR_SIZE       2 * DNET_ID_SIZE + 4

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
#ifndef O_LARGEFILE
#define O_LARGEFILE		0
#endif
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
 * Default wait timeout in seconds.
 */
#define DNET_DEFAULT_WAIT_TIMEOUT_SEC	5

/*
 * Default check timeout in seconds.
 */
#define DNET_DEFAULT_CHECK_TIMEOUT_SEC	60

#define DNET_DEFAULT_CACHE_SYNC_TIMEOUT_SEC 30

#define DNET_DEFAULT_STALL_TRANSACTIONS 3

#define DNET_DEFAULT_INDEXES_SHARD_COUNT 16

#define DNET_DEFAULT_CACHES_NUMBER 16

#define DNET_DEFAULT_CACHE_PAGES_NUMBER 1

#define DNET_DEFAULT_MONITOR_TOP_K 50

#define DNET_DEFAULT_MONITOR_TOP_EVENTS_SIZE (10000*100)

#define DNET_DEFAULT_MONITOR_TOP_PERIOD 300

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef dnet_offsetof
#ifdef __compiler_offsetof
#define dnet_offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define dnet_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

/* checksum size, must be enough to store sha512 hash */
#define DNET_CSUM_SIZE		64

/* kernel (pohmelfs) provides own defines for byteorder changes */
#ifndef __KERNEL__
#ifdef WORDS_BIGENDIAN

#define dnet_bswap16(x)		((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

#define dnet_bswap32(x) \
     ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |		      \
      (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

#define dnet_bswap64(x) \
     ((((x) & 0xff00000000000000ull) >> 56)				      \
      | (((x) & 0x00ff000000000000ull) >> 40)				      \
      | (((x) & 0x0000ff0000000000ull) >> 24)				      \
      | (((x) & 0x000000ff00000000ull) >> 8)				      \
      | (((x) & 0x00000000ff000000ull) << 8)				      \
      | (((x) & 0x0000000000ff0000ull) << 24)				      \
      | (((x) & 0x000000000000ff00ull) << 40)				      \
      | (((x) & 0x00000000000000ffull) << 56))
#else
#define dnet_bswap16(x) (x)
#define dnet_bswap32(x) (x)
#define dnet_bswap64(x) (x)
#endif
#endif

#define DIFF(s, e) ((e).tv_sec - (s).tv_sec) * 1000000 + ((e).tv_usec - (s).tv_usec)

#endif /* __DNET_CORE_H */
