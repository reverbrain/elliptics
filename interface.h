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

#ifndef __INTERFACE_H
#define __INTERFACE_H

#include "elliptics.h"

static inline struct el_cmd *dnet_trans_cmd(struct dnet_trans *t)
{
	if (t)
		return &t->cmd;
	return NULL;
}

static inline void *dnet_trans_private(struct dnet_trans *t)
{
	if (t)
		return t->priv;
	return NULL;
}

static inline void *dnet_trans_data(struct dnet_trans *t)
{
	if (t)
		return t->data;
	return NULL;
}

int dnet_read_object(struct dnet_node *n, struct el_io_attr *io,
	int (* complete)(struct dnet_trans *t, struct dnet_net_state *st), void *priv);
int dnet_read_file(struct dnet_node *n, char *file, __u64 offset, __u64 size);

int dnet_write_object(struct dnet_node *n, unsigned char *id, struct el_io_attr *io,
		int (* complete)(struct dnet_trans *t, struct dnet_net_state *st), void *priv,
		void *data);
int dnet_update_file(struct dnet_node *n, char *file, off_t offset, void *data, unsigned int size, int append);
int dnet_write_file(struct dnet_node *n, char *file);

#define DNET_MAX_ADDRLEN		256
#define DNET_MAX_PORTLEN		8

struct dnet_config
{
	unsigned char		id[EL_ID_SIZE];

	int			sock_type, proto, family;

	char			addr[DNET_MAX_ADDRLEN];
	char			port[DNET_MAX_PORTLEN];
};

int dnet_add_transform(struct dnet_node *n, void *priv, char *name,
	int (* transform)(void *priv, void *src, __u64 size, void *dst, unsigned int *dsize, unsigned int flags));
int dnet_remove_transform(struct dnet_node *n, char *name);

struct dnet_node *dnet_node_create(struct dnet_config *);
void dnet_node_destroy(struct dnet_node *n);

int dnet_add_state(struct dnet_node *n, struct dnet_config *cfg);
int dnet_join(struct dnet_node *n);
int dnet_setup_root(struct dnet_node *n, char *root);

#endif /* __INTERFACE_H */
