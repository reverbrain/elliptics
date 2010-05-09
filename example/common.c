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

static int dnet_common_send_upload_transactions(struct dnet_node *n, struct dnet_io_control *ctl)
{
	int err, num = 0;
	struct dnet_io_control hctl;
	struct dnet_history_entry e;
	uint32_t flags = ctl->io.flags;

	err = dnet_trans_create_send(n, ctl);
	if (err)
		goto err_out_exit;

	num++;

	if (!(ctl->aflags & DNET_ATTR_DIRECT_TRANSACTION)) {
		memset(&hctl, 0, sizeof(hctl));

		memcpy(hctl.addr, ctl->io.id, DNET_ID_SIZE);
		memcpy(hctl.io.origin, ctl->io.id, DNET_ID_SIZE);
		memcpy(hctl.io.id, ctl->io.id, DNET_ID_SIZE);

		dnet_setup_history_entry(&e, ctl->io.origin, ctl->io.size, ctl->io.offset, flags);

		hctl.priv = ctl->priv;
		hctl.complete = ctl->complete;
		hctl.cmd = DNET_CMD_WRITE;
		hctl.aflags = 0;
		hctl.cflags = DNET_FLAGS_NEED_ACK;
		hctl.fd = -1;
		hctl.local_offset = 0;
		hctl.adata = NULL;
		hctl.asize = 0;

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
		void *data, uint64_t size, int version, int pos,
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
	}

	err = dnet_common_send_upload_transactions(n, &ctl);
	if (err <= 0)
		goto out_exit;
	return err;

out_exit:
	if (err > 0 || pos == old_pos)
		return 0;
	return err;
}

int dnet_common_write_object(struct dnet_node *n, char *obj, int len,
		void *data, uint64_t size, int version,
		int (* complete)(struct dnet_net_state *, struct dnet_cmd *, struct dnet_attr *, void *),
		void *priv)
{
	int err;
	int pos = 0, trans_num = 0;

	while (1) {
		err = dnet_common_write_object_raw(n, obj, len, data, size, version, pos, complete, priv);
		if (err <= 0)
			break;

		trans_num += err;
		pos++;
	}

	return trans_num;
}

int dnet_common_send_meta_transactions(struct dnet_node *n, char *obj, int len,
		char *hashes, int hashes_len)
{
	struct dnet_meta m;
	int err;
	char file[64];

	snprintf(file, sizeof(file), "/tmp/meta-%d", getpid());

	err = dnet_meta_read(n, obj, len, file);
	if (err && err != -ENOENT)
		goto err_out_exit;

	memset(&m, 0, sizeof(struct dnet_meta));
	m.type = DNET_META_TRANSFORM;
	m.size = hashes_len + 1; /* 0-byte */

	err = dnet_meta_create_file(n, file, &m, hashes);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to add transform metadata for object '%s': %d.\n",
				obj, err);
		goto err_out_unlink;
	}

	m.type = DNET_META_PARENT_OBJECT;
	m.size = len + 1; /* 0-byte */

	err = dnet_meta_write(n, &m, obj, obj, len, file);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to add/send parent metadata for '%s': %d.\n", 
				obj, err);
		goto err_out_unlink;
	}

err_out_unlink:
	unlink(file);
err_out_exit:
	return err;
}

