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

#ifndef __DNET_INTERFACE_H
#define __DNET_INTERFACE_H

#include <dnet/typedefs.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dnet_net_state;
struct dnet_node;

/*
 * Callback data structures.
 *
 * [dnet_cmd]
 * [dnet_attr] [attributes]
 *
 * [dnet_cmd] header when present shows number of attached bytes.
 * It should be equal to the al_attr structure at least in the
 * correct message, otherwise it should be discarded.
 * One can also check cmd->flags if it has DNET_FLAGS_MORE or
 * DNET_FLAGS_DESTROY bit set. The former means that callback
 * will be invoked again in the future and transaction is not
 * yet completed. The latter means that transaction is about
 * to be destroyed.
 */

/*
 * IO helpers.
 *
 * dnet_node is a node pointer returned by calling dnet_node_create()
 * dnet_io_attr contains IO details (size, offset and the checksum)
 * completion callback (if present) will be invoked when IO transaction is finished
 * private data will be stored in the appropriate transaction and can be obtained
 * when transaction completion callback is invoked. It will be automatically
 * freed when transaction is completed.
 */
int dnet_read_object(struct dnet_node *n, struct dnet_io_attr *io,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv, unsigned int aflags);
int dnet_read_file(struct dnet_node *n, char *file, uint64_t offset, uint64_t size, unsigned int aflags);

int dnet_write_object(struct dnet_node *n, unsigned char *id, struct dnet_io_attr *io,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv, void *data, unsigned int aflags);
int dnet_write_file(struct dnet_node *n, char *file, off_t offset, size_t size, int append, unsigned int aflags);

#define DNET_MAX_ADDRLEN		256
#define DNET_MAX_PORTLEN		8

/*
 * Node configuration interface.
 */
struct dnet_config
{
	/*
	 * Unique network-wide ID.
	 */
	unsigned char		id[DNET_ID_SIZE];

	/*
	 * Socket type (SOCK_STREAM, SOCK_DGRAM and so on),
	 * a protocol (IPPROTO_TCP for example) and
	 * a family (AF_INET, AF_INET6 and so on)
	 * of the appropriate socket. These parameters are
	 * sent in the lookup replies so that remote nodes
	 * could know how to connect to this one.
	 */
	int			sock_type, proto, family;

	/*
	 * Socket address/port suitable for the getaddrinfo().
	 */
	char			addr[DNET_MAX_ADDRLEN];
	char			port[DNET_MAX_PORTLEN];

	/*
	 * Wait timeout in seconds used for example to wait
	 * for remote content sync.
	 */
	unsigned int		wait_timeout;
};

/*
 * Transformation functions are used to create ID from the provided data content.
 * One can add/remove them in a run-time. init/update/final sequence is used
 * each time for every transformed block, update can be invoked multiple times
 * between init and final ones.
 */
int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* init)(void *priv),
	int (* update)(void *priv, void *src, uint64_t size,
		void *dst, unsigned int *dsize, unsigned int flags),
	int (* final)(void *priv, void *dst, unsigned int *dsize, unsigned int flags));
int dnet_remove_transform(struct dnet_node *n, char *name);

/*
 * Node creation/destruction callbacks. Node is a building block of the storage
 * and it is needed for every operation one may want to do with the network.
 */
struct dnet_node *dnet_node_create(struct dnet_config *);
void dnet_node_destroy(struct dnet_node *n);

/*
 * dnet_add_state() is used to add a node into the route list, the more
 * routes are added the less network lookups will be performed to send/receive
 * data requests.
 */
int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg);

/*
 * This is used to join the network. When function is completed, node will be
 * used to store data sent from the network.
 */
int dnet_join(struct dnet_node *n);

/*
 * Sets the root directory to store data objects.
 */
int dnet_setup_root(struct dnet_node *n, char *root);

static inline char *dnet_dump_id(unsigned char *id)
{
	unsigned int i;
	static char __dnet_dump_str[2 * DNET_ID_SIZE + 1];

	for (i=0; i<DNET_ID_SIZE; ++i)
		sprintf(&__dnet_dump_str[2*i], "%02x", id[i]);
	return __dnet_dump_str;
}

/*
 * Initialize private logging system.
 */
int dnet_log_init(struct dnet_node *n, void *priv,
		void (* log)(void *priv, const char *f, ...),
		void (* log_append)(void *priv, const char *f, ...));

/*
 * Send a shell command to the remote node for execution.
 */
int dnet_send_cmd(struct dnet_node *n, unsigned char *id, char *command);

/*
 * Must be called by the main thread to give up control
 * to the elliptics machinery sometime after node has joined the network.
 *
 * This will pick up disconnected states and rejoin them.
 */
int dnet_give_up_control(struct dnet_node *n);

/*
 * Lookup a node which hosts given ID.
 */
int dnet_lookup_object(struct dnet_node *n, unsigned char *id,
	int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
	void *priv);
int dnet_lookup(struct dnet_node *n, char *file);

#ifdef __cplusplus
}
#endif

#endif /* __DNET_INTERFACE_H */
