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

#ifndef __DNET_LOCK_H
#define __DNET_LOCK_H

#include <pthread.h>

#ifdef HAVE_PTHREAD_SPINLOCK
struct dnet_lock {
	pthread_spinlock_t	lock;
};

static inline int dnet_lock_init(struct dnet_lock *l)
{
	return -pthread_spin_init(&l->lock, 0);
}

static inline void dnet_lock_destroy(struct dnet_lock *l)
{
	pthread_spin_destroy(&l->lock);
}

static inline void dnet_lock_lock(struct dnet_lock *l)
{
	pthread_spin_lock(&l->lock);
}

static inline void dnet_lock_unlock(struct dnet_lock *l)
{
	pthread_spin_unlock(&l->lock);
}
#else
struct dnet_lock {
	pthread_mutex_t		lock;
};

static inline int dnet_lock_init(struct dnet_lock *l)
{
	return -pthread_mutex_init(&l->lock, NULL);
}

static inline void dnet_lock_destroy(struct dnet_lock *l)
{
	pthread_mutex_destroy(&l->lock);
}

static inline void dnet_lock_lock(struct dnet_lock *l)
{
	pthread_mutex_lock(&l->lock);
}

static inline void dnet_lock_unlock(struct dnet_lock *l)
{
	pthread_mutex_unlock(&l->lock);
}
#endif

#endif /* __DNET_LOCK_H */
