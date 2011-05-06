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

static const char *hparser_visit(const char *key, size_t keysz,
			const char *hdata, size_t datasz, size_t *sp __attribute((unused)), void *opq)
{
	KCDB *meta = opq;
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
	
	fprintf(stdout, "Processing key %.128s\n", id_str);

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
	mc.data = (unsigned char *)kcdbget(meta, (void *)key, DNET_ID_SIZE, &mc.size);
	if (!mc.data) {
		err = -kcdbecode(meta);
		fprintf(stdout, "%s: meta DB read failed "
			"err: %d: %s.\n", dnet_dump_id_str(id),
			err, kcecodename(-err));
		goto err_out_exit;
	}

	mp = dnet_meta_search_cust(&mc, DNET_META_GROUPS);
	if (!mp) {
		fprintf(stdout, "Groups was not found in meta DB\n");
		goto err_out_kcfree;
	}

	dnet_convert_meta(mp);
	if (mp->size % sizeof(int)) {
		fprintf(stdout, "Metadata is broken: entry size %u\n", mp->size);
		goto err_out_kcfree;
	}

	group_num = mp->size / sizeof(int);
	groups = (int *)mp->data;
	dnet_convert_meta(mp);
	fprintf(stdout, "%d groups found in meta\n", group_num);

	mp = dnet_meta_search_cust(&mc, DNET_META_UPDATE);
	if (!mp) {
		fprintf(stdout, "Meta update was not found in meta DB\n");
		mp = m = malloc(sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num);
		m->type = DNET_META_UPDATE;
		m->size = sizeof(struct dnet_meta_update) * group_num;
		memset(m->data, 0, m->size);
	} else {
		dnet_convert_meta(mp);
	}

	if (mp->size % sizeof(struct dnet_meta_update)) {
		fprintf(stdout, "Metadata is broken: entry size %u\n", mp->size);
		goto err_out_kcfree;
	}

	mu_num = mp->size / sizeof(struct dnet_meta_update);
	mu = (struct dnet_meta_update *)mp->data;
	dnet_convert_meta(mp);

	dnet_convert_history_entry(&hm.ent[hm.num-1]);
	fprintf(stdout, "Last update stamp %llu %llu\n", hm.ent[hm.num-1].tsec, hm.ent[hm.num-1].tnsec);

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
				goto err_out_kcfree;
			}
		}
	}

	if (m) {
		err = kcdbbegintran(meta, 1);
		if (!err) {
			err = -kcdbecode(meta);
			fprintf(stdout, "%s: meta DB transaction start failed "
				"err: %d: %s.\n", dnet_dump_id_str(id),
				err, kcecodename(-err));
			goto err_out_kcfree;
		}

		err = kcdbappend(meta, key, DNET_ID_SIZE, (void *)m, sizeof(struct dnet_meta) + sizeof(struct dnet_meta_update) * group_num);
		if (!err) {
			err = -kcdbecode(meta);
			fprintf(stdout, "%s: meta DB append failed "
				"err: %d: %s.\n", dnet_dump_id_str(id),
				err, kcecodename(-err));
			goto err_out_kcfree;
		}

		kcdbendtran(meta, 1);

	}

err_out_kcfree:
	if (m)
		free(m);
	kcfree(mc.data);
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
	char *history_name = NULL, *meta_name = NULL;
	unsigned long long offset, size;
	KCDB *history = NULL, *meta = NULL;
	char tstr[64];
	time_t t;
	struct tm *tm;

	size = offset = 0;

	while ((ch = getopt(argc, argv, "M:H:h")) != -1) {
		switch (ch) {
			case 'M':
				meta_name = optarg;
				break;
			case 'H':
				history_name = optarg;
				break;
			case 'h':
				hparser_usage(argv[0]);
		}
	}

	if (!meta_name || !history_name) {
		fprintf(stderr, "You have to provide history and meta database to convert.\n");
		hparser_usage(argv[0]);
	}

	printf("opening %s history database\n", history_name);
	history = kcdbnew();
	err = kcdbopen(history, history_name, KCOREADER | KCONOREPAIR);
	if (!err) {
		fprintf(stderr, "Failed to open history database '%s': %d.\n", history_name, -kcdbecode(history));
		goto err_out_exit;
	}

	printf("opening %s meta database\n", meta_name);
	meta = kcdbnew();
	err = kcdbopen(meta, meta_name, KCOWRITER);
	if (!err) {
		fprintf(stderr, "Failed to open meta database '%s': %d.\n", meta_name, -kcdbecode(meta));
		goto err_out_dbopen;
	}

	t = time(NULL);
	tm = localtime(&t);
	strftime(tstr, sizeof(tstr), "%F %R:%S %Z", tm);
	total = (unsigned long long)kcdbcount(history);
	fprintf(stderr, "%s: Total %llu records in history DB\n", tstr, total);

	err = kcdbiterate(history, hparser_visit, meta, 0);
	if (!err) {
		fprintf(stderr, "Failed to iterate history database '%s': %d.\n", history_name, -kcdbecode(history));
	}

	t = time(NULL);
	tm = localtime(&t);
	strftime(tstr, sizeof(tstr), "%F %R:%S %Z", tm);
	total = (unsigned long long)kcdbcount(history);
	fprintf(stderr, "%s: Totally processed %llu records from history DB\n", tstr, counter);

	err = kcdbclose(meta);
	if (!err)
		fprintf(stderr, "Failed to close meta database '%s': %d.\n", meta_name, -kcdbecode(history));
	kcdbdel(meta);
err_out_dbopen:
	err = kcdbclose(history);
	if (!err)
		fprintf(stderr, "Failed to close history database '%s': %d.\n", history_name, -kcdbecode(history));
	kcdbdel(history);

err_out_exit:
	return err;
}
