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

struct dnet_node;
struct dnet_config;

/*!
 * \internal
 *
 * Raw statistics provider which can be used from c code
 */
struct stat_provider_raw {

	/*!
	 * \internal
	 *
	 * User-defined private data for provider
	 */
	void		*stat_private;

	/*!
	 * \internal
	 *
	 * Callback which returns current statistics of provider in json format
	 * It will be called only when was requested for statistics
	 * \a priv - user-defined private data for provider
	 * \a categories - categories which statistics should be included to json
	 */
	const char*	(* json) (void *priv, uint64_t categories);

	/*!
	 * \internal
	 *
	 * Callback for stopping and clearing provider's data.
	 * It will be called once when the provider is no longer required
	 * \a priv - user-defined private data for provider
	 */
	void		(* stop) (void *priv);
};

/*!
 * \internal
 *
 * Initializes monitoring with specified configuration
 * If monitor would be successfully initialized
 * then n->monitor will contain pointer to it and
 * should be used in c functions
 */
int dnet_monitor_init(struct dnet_node *n, struct dnet_config *cfg);

/*!
 * \internal
 *
 * Unitializes monitor and resets n->monitor to 0
 */
void dnet_monitor_exit(struct dnet_node *n);

/*!
 * \internal
 *
 * Adds to \a monitor raw statistics provider \a stat
 * with \a name to the provider list
 */
void dnet_monitor_add_provider(struct dnet_node *n, struct stat_provider_raw stat, const char *name);

/*!
 * \internal
 * Removes statistics provider by \a name from \a monitor.
 */
void dnet_monitor_remove_provider(struct dnet_node *n, const char *name);

/*!
 * \internal
 *
 * Sends to \a monitor statistics some properties of executed command:
 * \a cmd - identifier of the command
 * \a trans - number of transaction
 * \a err - error code
 * \a cache - flag which shows was the command executed by cache
 * \a size - size of data that takes a part in command execution
 * \a time - time spended on command execution
 */
void dnet_monitor_stats_update(struct dnet_node *n, const struct dnet_cmd *cmd, const int trans,
                               const int err, const int cache,
                               const uint32_t size, const unsigned long time);

int dnet_monitor_process_cmd(struct dnet_net_state *orig, struct dnet_cmd *cmd, void *data);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_MONITOR_MONITOR_H */
