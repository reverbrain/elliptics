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

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#define __unused	__attribute__ ((unused))

struct dnet_crypto_engine
{
	char			name[DNET_MAX_NAME_LEN];

	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
};

static int dnet_digest_init(void *priv)
{
	struct dnet_crypto_engine *e = priv;
	EVP_DigestInit_ex(&e->mdctx, e->evp_md, NULL);
	return 0;
}

static int dnet_digest_update(void *priv, void *src, uint64_t size,
		void *dst __unused, unsigned int *dsize __unused,
		unsigned int flags __unused)
{
	struct dnet_crypto_engine *e = priv;
	EVP_DigestUpdate(&e->mdctx, src, size);
	return 0;
}

static int dnet_digest_final(void *priv, void *result, unsigned int *rsize, unsigned int flags __unused)
{
	struct dnet_crypto_engine *e = priv;
	unsigned int rs = *rsize;
	EVP_DigestFinal_ex(&e->mdctx, result, rsize);

	if (*rsize < rs)
		memset(result + *rsize, 0, rs - *rsize);
	EVP_MD_CTX_cleanup(&e->mdctx);
	return 0;
}

static int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
 	OpenSSL_add_all_digests();

	snprintf(e->name, sizeof(e->name), "%s", hash);
	e->evp_md = EVP_get_digestbyname(hash);
	if (!e->evp_md) {
		fprintf(stderr, "Failed to find algorithm '%s' implementation.\n", hash);
		return -ENOENT;
	}

	EVP_MD_CTX_init(&e->mdctx);

	printf("Successfully initialized '%s' hash.\n", hash);

	return 0;
}

static void dnet_example_log_append(void *priv, const char *f, ...)
{
	va_list ap;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	va_start(ap, f);
	vfprintf(stream, f, ap);
	va_end(ap);

	fflush(stream);
}

static void dnet_example_log(void *priv, const char *f, ...)
{
	char str[64];
	struct tm tm;
	struct timeval tv;
	va_list ap;
	FILE *stream = priv;

	if (!stream)
		stream = stdout;

	gettimeofday(&tv, NULL);
	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	fprintf(stream, "%s.%06lu %6ld ", str, tv.tv_usec, syscall(__NR_gettid));

	va_start(ap, f);
	vfprintf(stream, f, ap);
	va_end(ap);

	fflush(stream);
}

static int dnet_example_log_init(struct dnet_node *n, char *log)
{
	FILE *f = NULL;
	int err;

	if (log) {
		f = fopen(log, "a");
		if (!f) {
			err = -errno;
			fprintf(stderr, "Failed to open log file %s: %s.\n", log, strerror(errno));
			goto err_out_exit;
		}
	}

	err = dnet_log_init(n, f, dnet_example_log, dnet_example_log_append);
	if (err) {
		fprintf(stderr, "Failed to initialize dnet logger to use file %s.\n", log);
		goto err_out_close;
	}

	printf("Logging uses '%s' file now.\n", log);
	return 0;

err_out_close:
	fclose(f);
err_out_exit:
	return err;
}

#define DNET_CONF_COMMENT	'#'
#define DNET_CONF_DELIM		'='
#define DNET_CONF_ADDR_DELIM	':'
#define DNET_CONF_TIME_DELIM	'.'

static int dnet_parse_addr(char *addr, struct dnet_config *cfg)
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

static int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[2];
	unsigned int i, len = strlen(value);

	memset(id, 0, DNET_ID_SIZE);

	if (len/2 > DNET_ID_SIZE)
		len = DNET_ID_SIZE * 2;

	for (i=0; i<len / 2; i++) {
		ch[0] = value[2*i + 0];
		ch[1] = value[2*i + 1];

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	if (len & 1) {
		ch[0] = value[2*i + 0];
		ch[1] = '0';

		id[i] = (unsigned char)strtol((const char *)ch, NULL, 16);
	}

	printf("Node id: %s\n", dnet_dump_id(id));
	return 0;
}

static int dnet_background(void)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Failed to fork to background: %s.\n", strerror(errno));
		return -1;
	}

	if (pid != 0) {
		printf("Daemon pid: %d.\n", pid);
		exit(0);
	}

	if (setsid()) {
		fprintf(stderr, "Failed to create a new session: %s.\n", strerror(errno));
		return -1;
	}

	close(1);
	close(2);

	return 0;
}

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -j <join>            - join the network\n"
			"                        become a fair node which may store data from the other nodes\n"
			" -d root              - root directory to load/store the objects\n"
			" -W file              - write given file to the network storage\n"
			" -R file              - read given file from the network into the local storage\n"
			" -H hash              - OpenSSL hash to use as a transformation function\n"
			" -i id                - node's ID (zero by default)\n"
			" -I id                - exec command transaction id\n"
			" -c cmd               - execute given command on the remote node\n"
			" -l log               - log file. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync.\n"
			" ...                  - parameters can be repeated multiple times\n"
			"                        each time they correspond to the last added node\n"
			" -D <daemon>          - go background\n"
			, p);
}

int main(int argc, char *argv[])
{
	int trans_max = 5, trans_num = 0;
	int ch, err, join = 0, i, have_remote = 0, daemon = 0;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	struct dnet_crypto_engine *e, *trans[trans_max];
	char *log = NULL, *root = NULL, *readf = NULL, *writef = NULL, *cmd = NULL;
	unsigned char trans_id[DNET_ID_SIZE];

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "Dc:I:w:l:i:H:W:R:a:r:jd:h")) != -1) {
		switch (ch) {
			case 'D':
				daemon = 1;
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				log = optarg;
				break;
			case 'c':
				cmd = optarg;
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, trans_id);
				if (err)
					return err;
				break;
			case 'i':
				err = dnet_parse_numeric_id(optarg, cfg.id);
				if (err)
					return err;
				break;
			case 'a':
				err = dnet_parse_addr(optarg, &cfg);
				if (err)
					return err;
				break;
			case 'r':
				err = dnet_parse_addr(optarg, &rem);
				if (err)
					return err;
				have_remote = 1;
				break;
			case 'j':
				join = 1;
				break;
			case 'd':
				root = optarg;
				break;
			case 'W':
				writef = optarg;
				break;
			case 'R':
				readf = optarg;
				break;
			case 'H':
				if (trans_num == trans_max - 1) {
					fprintf(stderr, "Only %d transformation functions allowed in this example.\n",
							trans_max);
					break;
				}

				e = malloc(sizeof(struct dnet_crypto_engine));
				if (!e)
					return -ENOMEM;
				memset(e, 0, sizeof(struct dnet_crypto_engine));

				err = dnet_crypto_engine_init(e, optarg);
				if (err)
					return err;
				trans[trans_num++] = e;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}

	if (!log)
		fprintf(stderr, "No log file found, logging will be disabled.\n");

	if (daemon)
		dnet_background();

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	err = dnet_example_log_init(n, log);
	if (err)
		return err;

	for (i=0; i<trans_num; ++i) {
		err = dnet_add_transform(n, trans[i], trans[i]->name,
				dnet_digest_init,
				dnet_digest_update,
				dnet_digest_final);
		if (err)
			return err;
	}

	if (have_remote) {
		err = dnet_add_state(n, &rem);
		if (err)
			return err;
	}

	if (root) {
		err = dnet_setup_root(n, root);
		if (err)
			return err;
	}

	if (join) {
		err = dnet_join(n);
		if (err)
			return err;
	}

	if (writef) {
		err = dnet_write_file(n, writef, 0, 0, 0);
		if (err)
			return err;
	}

	if (readf) {
		err = dnet_read_file(n, readf, 0, 0);
		if (err)
			return err;
	}

	if (cmd) {
		err = dnet_send_cmd(n, trans_id, cmd);
		if (err)
			return err;
	}

	if (root) {
		dnet_give_up_control(n);
	}

	printf("Successfully executed given command.\n");

	return 0;
}

