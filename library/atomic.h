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

#ifndef __DNET_ATOMIC_H
#define __DNET_ATOMIC_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_LIBATOMIC_SUPPORT
#include <atomic/atomic.h>

#define atomic_init(a, v) atomic_set(a, v)
#elif defined HAVE_SYNC_ATOMIC_SUPPORT
typedef struct {
	volatile long		val;
} atomic_t;

static inline void atomic_set(atomic_t *a, long val)
{
	a->val = val;
}

#define atomic_init(a, v) atomic_set(a, v)

static inline int atomic_read(atomic_t *a)
{
	return a->val;
}

static inline void atomic_add(atomic_t *a, long v)
{
	(void)__sync_add_and_fetch(&a->val, v);
}

static inline void atomic_sub(atomic_t *a, long v)
{
	(void)__sync_sub_and_fetch(&a->val, v);
}

static inline long atomic_inc(atomic_t *a)
{
	return __sync_add_and_fetch(&a->val, 1);
}

static inline long atomic_dec(atomic_t *a)
{
	return __sync_sub_and_fetch(&a->val, 1);
}

#define atomic_dec_and_test(a) (atomic_dec(a) == 0)

#else

#include "lock.h"

typedef struct {
	volatile long		val;
	struct dnet_lock	lock;
} atomic_t;

static inline int atomic_init(atomic_t *a, int val)
{
	int err;

	err = dnet_lock_init(&a->lock);
	if (err)
		return -err;

	a->val = val;
	return 0;
}

static inline void atomic_set(atomic_t *a, int val)
{
	a->val = val;
}

static inline int atomic_read(atomic_t *a)
{
	return a->val;
}

static inline void atomic_add(atomic_t *a, int v)
{
	dnet_lock_lock(&a->lock);
	a->val += v;
	dnet_lock_unlock(&a->lock);
}

static inline void atomic_sub(atomic_t *a, int v)
{
	dnet_lock_lock(&a->lock);
	a->val -= v;
	dnet_lock_unlock(&a->lock);
}

static inline int atomic_inc(atomic_t *a)
{
	int res;

	dnet_lock_lock(&a->lock);
	res = ++a->val;
	dnet_lock_unlock(&a->lock);

	return res;
}

static inline int atomic_dec(atomic_t *a)
{
	int res;

	dnet_lock_lock(&a->lock);
	res = --a->val;
	dnet_lock_unlock(&a->lock);

	return res;
}

#define atomic_dec_and_test(a) (atomic_dec(a) == 0)

#endif

#ifdef __cplusplus
}
#endif

#endif /* __DNET_ATOMIC_H */
