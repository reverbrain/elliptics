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

struct dnet_crypto_engine
{
	char			name[EL_MAX_NAME_LEN];
	
	EVP_MD_CTX 		mdctx;
	const EVP_MD		*evp_md;
};

static int dnet_digest_init(void *priv)
{
	struct dnet_crypto_engine *e = priv;
	EVP_DigestInit_ex(&e->mdctx, e->evp_md, NULL);
	return 0;
}

static int dnet_digest_update(void *priv, void *src, __u64 size,
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
	EVP_DigestFinal_ex(&e->mdctx, result, rsize);
	EVP_MD_CTX_cleanup(&e->mdctx);
	return 0;
}

static int dnet_crypto_engine_init(struct dnet_crypto_engine *e, char *hash)
{
 	OpenSSL_add_all_digests();

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
	FILE *f;
	int err;

	f = fopen(log, "a");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open log file %s: %s.\n", log, strerror(errno));
		goto err_out_exit;
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

#define EL_CONF_COMMENT		'#'
#define EL_CONF_DELIM		'='
#define EL_CONF_ADDR_DELIM	':'
#define EL_CONF_TIME_DELIM	'.'

static int dnet_parse_addr(char *addr, struct dnet_config *cfg)
{
	char *fam, *port;

	fam = strrchr(addr, EL_CONF_ADDR_DELIM);
	if (!fam)
		goto err_out_print_wrong_param;
	*fam++ = 0;
	if (!fam)
		goto err_out_print_wrong_param;

	cfg->family = atoi(fam);

	port = strrchr(addr, EL_CONF_ADDR_DELIM);
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
				EL_CONF_ADDR_DELIM, EL_CONF_ADDR_DELIM);
	return -EINVAL;
}

static int dnet_parse_numeric_id(char *value, unsigned char *id)
{
	unsigned char ch[2];
	unsigned int i, len = strlen(value);

	memset(id, 0, EL_ID_SIZE);

	if (len/2 > EL_ID_SIZE)
		len = EL_ID_SIZE * 2;

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
			" -i id                - node's ID\n"
			" -l log               - log file. Default: stdout\n"
			" ...                  - parameters can be repeated multiple times\n"
			"                        each time they correspond to the last added node\n", p);
}

int main(int argc, char *argv[])
{
	int ch, err;
	struct dnet_node *n = NULL;
	struct dnet_config cfg;
	struct dnet_crypto_engine *e;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;

	while ((ch = getopt(argc, argv, "l:i:H:W:R:a:r:jd:h")) != -1) {
		switch (ch) {
			case 'l':
				if (n) {
					err = dnet_example_log_init(n, optarg);
					if (err)
						return err;
				}
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

				n = dnet_node_create(&cfg);
				if (!n)
					return -1;
				break;
			case 'r':
				if (!n)
					return -EINVAL;
				err = dnet_parse_addr(optarg, &cfg);
				if (err)
					return err;

				err = dnet_add_state(n, &cfg);
				if (err)
					return err;
				break;
			case 'j':
				if (!n)
					return -EINVAL;

				err = dnet_join(n);
				if (err)
					return err;
				break;
			case 'd':
				if (!n)
					return -EINVAL;
				err = dnet_setup_root(n, optarg);
				if (err)
					return err;
				break;
			case 'W':
				if (!n)
					return -EINVAL;
				err = dnet_write_file(n, optarg);
				if (err)
					return err;
				break;
			case 'R':
				if (!n)
					return -EINVAL;
				err = dnet_read_file(n, optarg, 0, 0);
				if (err)
					return err;
				break;
			case 'H':
				if (!n)
					return -EINVAL;

				e = malloc(sizeof(struct dnet_crypto_engine));
				if (!e)
					return -ENOMEM;
				memset(e, 0, sizeof(struct dnet_crypto_engine));

				err = dnet_crypto_engine_init(e, optarg);
				if (err)
					return err;

				err = dnet_add_transform(n, e, optarg,
						dnet_digest_init,
						dnet_digest_update,
						dnet_digest_final);
				if (err)
					return err;
				break;
			case 'h':
			default:
				dnet_usage(argv[0]);
				return -1;
		}
	}

	if (!n) {
		dnet_usage(argv[0]);
		return -1;
	}

	while (1)
		sleep(1);
	printf("Exiting.\n");

	return 0;
}

