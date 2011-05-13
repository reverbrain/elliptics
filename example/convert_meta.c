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
#include <sys/mman.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <kclangc.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "common.h"

//BUFFER_SIZE = 1MB
#define BUFFER_SIZE 1048576

static void hparser_usage(const char *p)
{
	fprintf(stderr, "Usage: %s args\n", p);
	fprintf(stderr, " -H                   - history database to parse\n"
			" -M                   - meta database to parse\n"
			" -h                   - this help\n");
	exit(-1);
}

uint64_t counter = 0;
uint64_t total = 0;

struct db_ptrs {
	KCDB *meta;
	KCDB *newmeta;
	char *buffer;
};

static const char *hparser_visit(const char *key, size_t keysz,
			const char *hdata, size_t datasz, size_t *sp __attribute((unused)), void *opq)
{
	//KCDB *meta = opq;
	struct db_ptrs *ptrs = opq;
	char *data = NULL;
	char id_str[2 * DNET_ID_SIZE + 1];
	struct dnet_history_map hm;
	struct dnet_meta_container mc;
	struct dnet_meta *mp, *m = NULL;
	struct dnet_meta_update *mu;
	int mu_num = 0;
	int err;
	int group_num = 0, *groups = NULL;
	int i, j;
	unsigned char id[DNET_ID_SIZE];
	char tstr[64];
	time_t t;
	struct tm *tm;

	if (keysz != DNET_ID_SIZE) {
		fprintf(stdout, "Incorrect key size\n");
		goto err_out_exit;
	}

	memcpy(id, key, DNET_ID_SIZE);
	dnet_dump_id_len_raw(id, DNET_ID_SIZE, id_str);
	
	fprintf(stdout, "Processing key %.128s  ", id_str);

	if (datasz % (int)sizeof(struct dnet_history_entry)) {
		fprintf(stdout, "Corrupted history record, "
				"its size %d must be multiple of %zu.\n",
				datasz, sizeof(struct dnet_history_entry));
		goto err_out_exit;
	}

	hm.ent = (struct dnet_history_entry *)hdata;
	hm.num = datasz / sizeof(struct dnet_history_entry);
	hm.size = datasz;

	dnet_setup_id(&mc.id, 0, id);
	data = kcdbget(ptrs->meta, (void *)key, DNET_ID_SIZE, &mc.size);
	if (!data) {
		err = -kcdbecode(ptrs->meta);
		fprintf(stdout, "failed. %s: meta DB read failed "
			"err: %d: %s.\n", dnet_dump_id_str(id),
			err, kcecodename(-err));
		goto err_out_exit;
	}

	if (mc.size > BUFFER_SIZE) {
		fprintf(stdout, "failed. Meta size=%d is too big\n", mc.size);
		goto err_out_kcfree;
	}

	mc.data = ptrs->buffer;
	memcpy(mc.data, data, mc.size);

	mp = dnet_meta_search_cust(&mc, DNET_META_GROUPS);
	if (!mp) {
		fprintf(stdout, "failed. Groups was not found in meta DB\n");
		goto err_out_kcfree;
	}

	dnet_convert_meta(mp);
	if (mp->size % sizeof(int)) {
		fprintf(stdout, "failed. Metadata is broken: entry size %u\n", mp->size);
		goto err_out_kcfree;
	}

	group_num = mp->size / sizeof(int);
	groups = (int *)mp->data;
	dnet_convert_meta(mp);

	mp = dnet_meta_search_cust(&mc, DNET_META_UPDATE);
	if (!mp) {
		// Add new meta structure after the end of current metadata
		if (mc.size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num > BUFFER_SIZE) {
			fprintf(stdout, "failed. New meta size=%d is too big\n", 
					mc.size + sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num);
			goto err_out_kcfree;
		}
		mp = m = mc.data + mc.size;
		mc.size += sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num;

		memset(m, 0, sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num);
		m->type = DNET_META_UPDATE;
		m->size = sizeof(struct dnet_meta_update) * group_num;
		memset(m->data, 0, m->size);
	} else {
		dnet_convert_meta(mp);
	}

	if (mp->size % sizeof(struct dnet_meta_update)) {
		fprintf(stdout, "failed. Metadata is broken: entry size %u\n", mp->size);
		goto err_out_kcfree;
	}

	mu_num = mp->size / sizeof(struct dnet_meta_update);
	mu = (struct dnet_meta_update *)mp->data;
	dnet_convert_meta(mp);

	dnet_convert_history_entry(&hm.ent[hm.num-1]);

	for (i = 0; i < group_num; ++i) {
		if (m) {
			mu[i].group_id = groups[i];
			mu[i].tsec = hm.ent[hm.num-1].tsec;
			mu[i].tnsec = hm.ent[hm.num-1].tnsec;
			mu[i].flags = hm.ent[hm.num-1].flags & DNET_IO_FLAGS_REMOVED;
			dnet_convert_meta_update(&mu[i]);
		} else {
			for (j = 0; j < mu_num; ++j) {
				if (mu[i].group_id == groups[i])
					break;
			}
			if (j == mu_num) {
				fprintf(stdout, "Group %d was not found in meta DB\n", groups[i]);
			}
		}
	}

	// Commit every 1000 records.
	if (!(counter % 1000)) {
		if (counter > 0) {
			kcdbendtran(ptrs->newmeta, 1);
		}

		err = kcdbbegintran(ptrs->newmeta, 1);
		if (!err) {
			err = -kcdbecode(ptrs->newmeta);
			fprintf(stdout, "%s: meta DB transaction start failed "
				"err: %d: %s.\n", dnet_dump_id_str(id),
				err, kcecodename(-err));
			goto err_out_kcfree;
		}
	}

	err = kcdbset(ptrs->newmeta, key, DNET_ID_SIZE, (void *)mc.data, mc.size);
	if (!err) {
		err = -kcdbecode(ptrs->newmeta);
		fprintf(stdout, "%s: meta DB append failed "
			"err: %d: %s.\n", dnet_dump_id_str(id),
			err, kcecodename(-err));
		goto err_out_kcfree;
	}


	fprintf(stdout, "ok. Last update stamp %llu %llu\n", hm.ent[hm.num-1].tsec, hm.ent[hm.num-1].tnsec);

err_out_kcfree:
	kcfree(data);
err_out_exit:
	counter++;
	if (!(counter % 10000)) {
		t = time(NULL);
		tm = localtime(&t);
		strftime(tstr, sizeof(tstr), "%F %R:%S %Z", tm);
		fprintf(stderr, "%s: %llu/%llu records processed\n", tstr, counter, total);
	}

	return KCVISNOP;
}

int main(int argc, char *argv[])
{
	int err, ch;
	char *history_name = NULL, *meta_name = NULL, *newmeta_name = NULL;
	unsigned long long offset, size;
	KCDB *history = NULL, *meta = NULL, *newmeta = NULL;
	char tstr[64];
	time_t t;
	struct tm *tm;
	struct db_ptrs ptrs;

	size = offset = 0;

	while ((ch = getopt(argc, argv, "M:H:N:h")) != -1) {
		switch (ch) {
			case 'M':
				meta_name = optarg;
				break;
			case 'H':
				history_name = optarg;
				break;
			case 'N':
				newmeta_name = optarg;
				break;
			case 'h':
				hparser_usage(argv[0]);
		}
	}

	if (!meta_name || !history_name || !newmeta_name) {
		fprintf(stderr, "You have to provide history and meta database to convert.\n");
		hparser_usage(argv[0]);
	}

	memset(&ptrs, 0, sizeof(struct db_ptrs));

	printf("opening %s history database\n", history_name);
	history = kcdbnew();
	err = kcdbopen(history, history_name, KCOREADER | KCONOREPAIR);
	if (!err) {
		fprintf(stderr, "Failed to open history database '%s': %d.\n", history_name, -kcdbecode(history));
		goto err_out_exit;
	}

	printf("opening %s meta database\n", meta_name);
	meta = kcdbnew();
	err = kcdbopen(meta, meta_name, KCOREADER | KCONOREPAIR);
	if (!err) {
		fprintf(stderr, "Failed to open meta database '%s': %d.\n", meta_name, -kcdbecode(meta));
		goto err_out_dbopen;
	}

	printf("opening %s new meta database\n", newmeta_name);
	newmeta = kcdbnew();
	err = kcdbopen(newmeta, newmeta_name, KCOWRITER | KCOCREATE);
	if (!err) {
		fprintf(stderr, "Failed to open meta database '%s': %d.\n", newmeta_name, -kcdbecode(newmeta));
		goto err_out_dbopen2;
	}

	ptrs.meta = meta;
	ptrs.newmeta = newmeta;
	ptrs.buffer = malloc(BUFFER_SIZE);
	if (!ptrs.buffer) {
		fprintf(stderr, "Failed to allocate memory for buffer\n");
		goto err_out_dbopen3;
	}

	t = time(NULL);
	tm = localtime(&t);
	strftime(tstr, sizeof(tstr), "%F %R:%S %Z", tm);
	total = (unsigned long long)kcdbcount(history);
	fprintf(stderr, "%s: Total %llu records in history DB\n", tstr, total);

	err = kcdbiterate(history, hparser_visit, &ptrs, 0);
	if (!err) {
		fprintf(stderr, "Failed to iterate history database '%s': %d.\n", history_name, -kcdbecode(history));
	}
	kcdbendtran(newmeta, 1);

	t = time(NULL);
	tm = localtime(&t);
	strftime(tstr, sizeof(tstr), "%F %R:%S %Z", tm);
	total = (unsigned long long)kcdbcount(history);
	fprintf(stderr, "%s: Totally processed %llu records from history DB\n", tstr, counter);

err_out_dbopen3:
	err = kcdbclose(newmeta);
	if (!err)
		fprintf(stderr, "Failed to close new meta database '%s': %d.\n", newmeta_name, -kcdbecode(newmeta));
	kcdbdel(newmeta);
err_out_dbopen2:
	err = kcdbclose(meta);
	if (!err)
		fprintf(stderr, "Failed to close meta database '%s': %d.\n", meta_name, -kcdbecode(meta));
	kcdbdel(meta);
err_out_dbopen:
	err = kcdbclose(history);
	if (!err)
		fprintf(stderr, "Failed to close history database '%s': %d.\n", history_name, -kcdbecode(history));
	kcdbdel(history);

err_out_exit:
	return err;
}
