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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "elliptics.h"
#include "interface.h"

static struct dnet_node *dnet_node_alloc(int sock_type, int proto)
{
	struct dnet_node *n;
	int err;

	n = malloc(sizeof(struct dnet_node));
	if (!n)
		return NULL;

	memset(n, 0, sizeof(struct dnet_node));

	n->sock_type = sock_type;
	n->proto = proto;
	n->trans = 0;
	n->trans_root = RB_ROOT;

	err = pthread_mutex_init(&n->state_lock, NULL);
	if (err) {
		ulog_err("Failed to initialize state lock: err: %d", err);
		goto err_out_free;
	}
	
	err = pthread_mutex_init(&n->trans_lock, NULL);
	if (err) {
		ulog_err("Failed to initialize transaction lock: err: %d", err);
		goto err_out_destroy_state;
	}
	
	err = pthread_mutex_init(&n->tlock, NULL);
	if (err) {
		ulog_err("Failed to initialize transformation lock: err: %d", err);
		goto err_out_destroy_trans;
	}

	INIT_LIST_HEAD(&n->tlist);
	INIT_LIST_HEAD(&n->state_list);
	INIT_LIST_HEAD(&n->empty_state_list);

	return n;

err_out_destroy_trans:
	pthread_mutex_destroy(&n->trans_lock);
err_out_destroy_state:
	pthread_mutex_destroy(&n->state_lock);
err_out_free:
	free(n);
	return NULL;
}

void dnet_state_remove(struct dnet_net_state *st)
{
	struct dnet_node *n = st->n;

	pthread_mutex_lock(&n->state_lock);
	list_del(&st->state_entry);
	pthread_mutex_unlock(&n->state_lock);
}

int dnet_state_insert(struct dnet_net_state *new)
{
	struct dnet_node *n = new->n;
	struct dnet_net_state *st;
	int err = 1;

	new->empty = 0;

	pthread_mutex_lock(&n->state_lock);

	list_for_each_entry(st, &n->state_list, state_entry) {
		err = dnet_id_cmp(st->id, new->id);

		ulog("st: %s, ", dnet_dump_id(st->id));
		uloga("new: %s, cmp: %d.\n", dnet_dump_id(new->id), err);

		if (!err) {
			ulog("%s: state exists: old: %s:%d, new: %s:%d.\n", dnet_dump_id(new->id),
				dnet_server_convert_addr(&st->addr, st->addr_len),
				dnet_server_convert_port(&st->addr, st->addr_len),
				dnet_server_convert_addr(&new->addr, new->addr_len),
				dnet_server_convert_port(&new->addr, new->addr_len));
			break;
		}

		if (err < 0) {
			ulog("adding before %s.\n", dnet_dump_id(st->id));
			list_add_tail(&new->state_entry, &st->state_entry);
			break;
		}
	}

	if (err > 0) {
		ulog("adding to the end.\n");
		list_add_tail(&new->state_entry, &n->state_list);
	}

	if (err) {
		ulog("%s: node list dump:\n", dnet_dump_id(new->id));
		list_for_each_entry(st, &n->state_list, state_entry) {
			ulog("      id: %s [%02x], addr: %s:%d.\n", dnet_dump_id(st->id), st->id[0],
				dnet_server_convert_addr(&st->addr, st->addr_len),
				dnet_server_convert_port(&st->addr, st->addr_len));
		}
		uloga("\n");
	}

	pthread_mutex_unlock(&n->state_lock);

	if (!err)
		err = -EEXIST;
	else
		err = 0;

	return err;
}

int dnet_state_move(struct dnet_net_state *st)
{
	dnet_state_remove(st);
	return dnet_state_insert(st);
}

struct dnet_net_state *dnet_state_search(struct dnet_node *n, unsigned char *id, struct dnet_net_state *self)
{
	struct dnet_net_state *st = NULL;
	int err = 1;

	pthread_mutex_lock(&n->state_lock);

	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == self)
			continue;

		err = dnet_id_cmp(st->id, id);

		if (err <= 0) {
			dnet_state_get(st);
			break;
		}
	}

	if (err > 0)
		st = NULL;

	pthread_mutex_unlock(&n->state_lock);

	return st;
}

struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, struct dnet_net_state *self)
{
	struct dnet_net_state *st = NULL;
	int err = -ENOENT;

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry(st, &n->state_list, state_entry) {
		if (st == self)
			continue;

		dnet_state_get(st);
		err = 0;
		break;
	}
	pthread_mutex_unlock(&n->state_lock);

	if (err)
		return NULL;

	return st;
}

static void *dnet_server_func(void *data)
{
	struct dnet_net_state *main_st = data;
	struct dnet_net_state *st;
	struct dnet_node *n = main_st->n;
	int cs;
	struct sockaddr addr;
	socklen_t socklen = sizeof(addr);

	while (!n->need_exit) {
		cs = accept(n->listen_socket, &addr, &socklen);
		if (cs <= 0) {
			ulog_err("%s: failed to accept new client", dnet_dump_id(n->id));
			continue;
		}

		ulog("%s: accepted client %s:%d.\n", dnet_dump_id(n->id),
				dnet_server_convert_addr(&addr, socklen),
				dnet_server_convert_port(&addr, socklen));

		fcntl(cs, F_SETFL, O_NONBLOCK);

		st = dnet_state_create(n, NULL, &addr, socklen, cs, dnet_state_process);
		if (!st) {
			close(cs);
			ulog("%s: disconnected client %s:%d.\n", dnet_dump_id(n->id),
					dnet_server_convert_addr(&addr, socklen),
					dnet_server_convert_port(&addr, socklen));
		}
	}

	return NULL;
}

struct dnet_node *dnet_node_create(struct dnet_config *cfg)
{
	struct dnet_node *n;
	int err = -ENOMEM;

	n = dnet_node_alloc(cfg->sock_type, cfg->proto);
	if (!n)
		goto err_out_exit;

	memcpy(n->id, cfg->id, EL_ID_SIZE);
	n->proto = cfg->proto;
	n->sock_type = cfg->sock_type;

	err = dnet_socket_create(cfg, &n->addr, &n->addr_len, 1);
	if (err < 0)
		goto err_out_free;

	n->listen_socket = err;

	n->st = dnet_state_create(n, n->id, &n->addr, n->addr_len,
			n->listen_socket, dnet_server_func);
	if (!n->st)
		goto err_out_sock_close;

	ulog("%s: new node has been created at %s.\n", dnet_dump_id(n->id), dnet_dump_node(n));
	return n;

err_out_sock_close:
	close(n->listen_socket);
err_out_free:
	free(n);
err_out_exit:
	return NULL;
}

void dnet_node_destroy(struct dnet_node *n)
{
	struct dnet_net_state *st, *tmp;

	ulog("%s: destroying node at %s.\n", dnet_dump_id(n->id), dnet_dump_node(n));

	pthread_mutex_lock(&n->state_lock);
	list_for_each_entry_safe(st, tmp, &n->state_list, state_entry) {
		list_del(&st->state_entry);
		pthread_join(st->tid, NULL);

		dnet_state_put(st);
	}
	pthread_mutex_unlock(&n->state_lock);

	close(n->listen_socket);
	
	pthread_mutex_destroy(&n->state_lock);
	pthread_mutex_destroy(&n->trans_lock);

	free(n->root);
	free(n);
}

