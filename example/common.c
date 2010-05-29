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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>

#include <dnet/packet.h>
#include <dnet/interface.h>

#include "common.h"

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIM		'='
#define DNET_CONF_ADDR_DELIM	':'
#define DNET_CONF_TIME_DELIM	'.'

int dnet_parse_addr(char *addr, struct dnet_config *cfg)
{
	char *fam, *port;

	fam = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!fam)
		goto err_out_print_wrong_param;
	*fam++ = 0;
	if (!fam)
		goto err_out_print_wrong_param;

	cfg->family = atoi(fam);

	port = strrchr(addr, DNET_CONF_ADDR_DELIM);
	if (!port)
		goto err_out_print_wrong_param;
	*port++ = 0;
	if (!port)
		goto err_out_print_wrong_param;

	memset(cfg->addr, 0, sizeof(cfg->addr));
	memset(cfg->port, 0, sizeof(cfg->port));

	snprintf(cfg->addr, sizeof(cfg->addr), "%s", addr);
	snprintf(cfg->port, sizeof(cfg->port), "%s", port);

	return 0;

err_out_print_wrong_param:
	fprintf(stderr, "Wrong address parameter, should be 'addr%cport%cfamily'.\n",
				DNET_CONF_ADDR_DELIM, DNET_CONF_ADDR_DELIM);
	return -EINVAL;
}

int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[5];
	unsigned int i, len = strlen(value);

	memset(id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	ch[0] = '0';
	ch[1] = 'x';
	ch[4] = '\0';
	for (i=0; i<len / 2; i++) {
		ch[2] = value[2*i + 0];
		ch[3] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[2] = value[2*i + 0];
		ch[3] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	return 0;
}

void dnet_common_log(void *priv, uint32_t mask, const char *msg)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %1x: %s", str, tv.tv_usec, mask, msg);
	fflush(stream);
}

static void dnet_common_convert_adata(void *adata, struct dnet_io_attr *ioattr)
{
	/*
	 * This is a bit ugly block, since we break common code to update inner data...
	 * But originally it lived in the place where this was appropriate, and even now
	 * it is used the way this processing is needed.
	 */

	if (adata) {
		struct dnet_attr *a = adata;

		if (a->cmd == DNET_CMD_WRITE) {
			struct dnet_io_attr *io = (struct dnet_io_attr *)(a + 1);

			memcpy(io->origin, ioattr->origin, DNET_ID_SIZE);
			memcpy(io->id, ioattr->id, DNET_ID_SIZE);

			dnet_convert_io_attr(io);
		}
	}
}

static int dnet_common_send_upload_transactions(struct dnet_node *n, struct dnet_io_control *ctl,
		void *adata, uint32_t asize)
{
	int err, num = 0;
	struct dnet_io_control hctl;
	struct dnet_history_entry e;
	uint32_t flags = ctl->io.flags | DNET_IO_FLAGS_PARENT;

	dnet_common_convert_adata(adata, &ctl->io);

	err = dnet_trans_create_send(n, ctl);
	if (err)
		goto err_out_exit;

	num++;

	if (!(ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION)) {
		memset(&hctl, 0, sizeof(hctl));

		memcpy(hctl.addr, ctl->io.id, DNET_ID_SIZE);
		memcpy(hctl.io.origin, ctl->io.id, DNET_ID_SIZE);
		memcpy(hctl.io.id, ctl->io.id, DNET_ID_SIZE);

		dnet_common_convert_adata(adata, &hctl.io);

		hctl.adata = adata;
		hctl.asize = asize;

		if (ctl->ts.tv_sec)
			dnet_setup_history_entry(&e, ctl->io.origin, ctl->io.size, ctl->io.offset, &ctl->ts, flags);
		else
			dnet_setup_history_entry(&e, ctl->io.origin, ctl->io.size, ctl->io.offset, NULL, flags);

		hctl.priv = ctl->priv;
		hctl.complete = ctl->complete;
		hctl.cmd = DNET_CMD_WRITE;
		hctl.aflags = 0;
		hctl.cflags = DNET_FLAGS_NEED_ACK;
		hctl.fd = -1;
		hctl.local_offset = 0;

		hctl.data = &e;

		hctl.io.size = sizeof(struct dnet_history_entry);
		hctl.io.offset = 0;
		hctl.io.flags = flags | DNET_IO_FLAGS_HISTORY | DNET_IO_FLAGS_APPEND;

		err = dnet_trans_create_send(n, &hctl);
		if (err)
			goto err_out_exit;

		num++;
	}

err_out_exit:
	return num;
}

static int dnet_common_write_object_raw(struct dnet_node *n, char *obj, unsigned int len,
		void *adata, uint32_t asize, int history_only,
		void *data, uint64_t size, int version, int pos, struct timespec *ts,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv)
{
	struct dnet_io_control ctl;
	int old_pos = pos, err;
	unsigned int rsize;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = data;
	ctl.fd = -1;

	ctl.complete = complete;
	ctl.priv = priv;

	if (!history_only) {
		ctl.adata = adata;
		ctl.asize = asize;
	}

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = DNET_ATTR_NO_TRANSACTION_SPLIT;

	/*
	 * We want to store transaction logs to get modification time.
	 */
	//ctl.io.flags = DNET_IO_FLAGS_NO_HISTORY_UPDATE;
	ctl.io.flags = 0;
	ctl.io.size = size;
	ctl.io.offset = 0;

	if (ts)
		ctl.ts = *ts;

	pos = old_pos;
	rsize = DNET_ID_SIZE;
	err = dnet_transform(n, obj, len, ctl.io.id, ctl.addr, &rsize, &pos);
	if (err || pos == old_pos)
		goto out_exit;
	
	if (version != -1) {
		/*
		 * ctl.addr is used for cmd.id, so the last assignment is correct, since
		 * we first send transaction with the data and only then history one.
		 */
		pos = old_pos;
		rsize = DNET_ID_SIZE;
		err = dnet_transform(n, data, size, ctl.io.origin, ctl.addr, &rsize, &pos);
		if (err || pos == old_pos)
			goto out_exit;

		dnet_common_convert_id_version(ctl.io.origin, version);
		dnet_common_convert_id_version(ctl.addr, version);

		ctl.io.flags |= DNET_IO_FLAGS_ID_VERSION | DNET_IO_FLAGS_ID_CONTENT;
	} else {
		ctl.aflags |= DNET_ATTR_DIRECT_TRANSACTION;
		memcpy(ctl.io.origin, ctl.io.id, DNET_ID_SIZE);
		ctl.io.flags |= DNET_IO_FLAGS_PARENT;
	}

	err = dnet_common_send_upload_transactions(n, &ctl, adata, asize);
	if (err <= 0)
		goto out_exit;
	return err;

out_exit:
	if (err > 0 || pos == old_pos)
		return 0;
	return err;
}

int dnet_common_write_object(struct dnet_node *n, char *obj, int len,
		void *adata, uint32_t asize, int history_only,
		void *data, uint64_t size, int version, struct timespec *ts, 
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv)
{
	int err;
	int pos = 0, trans_num = 0;

	while (1) {
		err = dnet_common_write_object_raw(n, obj, len, adata, asize, history_only,
				data, size, version, pos, ts, complete, priv);
		if (err <= 0)
			break;

		trans_num += err;
		pos++;
	}

	return trans_num;
}

static void dnet_common_setup_meta_data(char *data, char *obj, int len, char *hash, int hlen)
{
	struct dnet_attr *a = (struct dnet_attr *)data;
	struct dnet_io_attr *io = (struct dnet_io_attr *)(a + 1);
	struct dnet_meta *mo = (struct dnet_meta *)(io + 1);
	struct dnet_meta *mh = (struct dnet_meta *)(((void *)(mo + 1)) + len + 1);

	a->size = sizeof(struct dnet_io_attr) + sizeof(struct dnet_meta) * 2 + len + hlen + 2; /* 0-bytes */
	a->cmd = DNET_CMD_WRITE;
	a->flags = 0;

	io->size = a->size - sizeof(struct dnet_io_attr);
	io->flags = DNET_IO_FLAGS_META | DNET_IO_FLAGS_HISTORY;
	io->offset = 0;

	mo->type = DNET_META_PARENT_OBJECT;
	mo->size = len + 1; /* 0-byte */
	snprintf((char *)mo->data, mo->size, "%s", obj);
	dnet_convert_meta(mo);

	mh->type = DNET_META_TRANSFORM;
	mh->size = hlen + 1;
	snprintf((char *)mh->data, mh->size, "%s", hash);
	dnet_convert_meta(mh);
}


int dnet_common_write_object_meta(struct dnet_node *n, char *obj, int len,
		char *hash, int hlen, int history_only,
		void *data, uint64_t size, int version, struct timespec *ts, 
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv)
{
	char adata[len + hlen + sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr) + sizeof(struct dnet_meta)*2 + 2 /* 0-bytes */];

	memset(adata, 0, sizeof(adata));
	dnet_common_setup_meta_data(adata, obj, len, hash, hlen);

	return dnet_common_write_object(n, obj, len, adata, sizeof(adata), history_only, data, size, version, ts, complete, priv);
}
