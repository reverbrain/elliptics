/*
 * Copyright 2013+ Kirill Smorodinnikov <shaitkir@gmail.com>
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
 * You should have received a copy of the GNU General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __DNET_MONITOR_MONITOR_H
#define __DNET_MONITOR_MONITOR_H

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Reserved monitor categories for bad and list requests
#define DNET_MONITOR_BAD			-3
#define DNET_MONITOR_NOT_FOUND		-2
#define DNET_MONITOR_LIST			-1

// Real monitor categories
#define DNET_MONITOR_ALL			0
#define DNET_MONITOR_CACHE			1
#define DNET_MONITOR_IO_QUEUE		2
#define DNET_MONITOR_COMMANDS		3
#define DNET_MONITOR_IO_HISTOGRAMS	4

struct dnet_node;
struct dnet_config;

struct stat_provider_raw {
	void		*stat_private;
	const char*	(* json) (void *priv);
	void		(* stop) (void *priv);
	int		(* check_category) (void *priv, int category);
};

void dnet_monitor_log(void *monitor);

int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg);
void dnet_monitor_exit(struct dnet_node *n);

void dnet_monitor_add_provider(void* monitor, struct stat_provider_raw stat, const char *name);

void monitor_command_counter(void *monitor, const int cmd, const int trans,
                             const int err, const int cache,
                             const uint32_t size, const unsigned long time);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_MONITOR_MONITOR_H */
