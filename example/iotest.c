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
#include <sys/mman.h>

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>

#include <netinet/in.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

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

static void dnet_example_log_append(void *priv, uint32_t mask __unused, const char *f, ...)
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

static void dnet_example_log(void *priv, uint32_t mask __unused, const char *f, ...)
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

	fprintf(stream, "%s.%06lu ", str, tv.tv_usec);

	va_start(ap, f);
	vfprintf(stream, f, ap);
	va_end(ap);

	fflush(stream);
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

static unsigned long long iotest_bytes;
static unsigned long long iotest_completed_error, iotest_completed;
struct timeval iotest_start;

static void iotest_alarm(int num __unused)
{
	double speed;
	struct timeval t;
	long usec;

	gettimeofday(&t, NULL);

	usec = t.tv_usec - iotest_start.tv_usec;
	usec += 1000000 * (t.tv_sec - iotest_start.tv_sec);

	speed = (double)iotest_bytes/ (double)usec * 1000000 / (1024 * 1024);

	printf("bytes: %llu, chunks: %llu, errors: %llu, speed: %.3f MB/s\n",
			iotest_bytes, iotest_completed, iotest_completed_error, speed);
}

static int iotest_complete(struct dnet_net_state *st __unused, struct dnet_cmd *cmd, struct dnet_attr *attr __unused, void *priv)
{
	if (!cmd || !cmd->size || cmd->status) {
		if (!cmd || cmd->status)
			iotest_completed_error++;

		if (!cmd->size) {
			unsigned long bytes = (unsigned long)priv;
			iotest_completed++;
			iotest_bytes += bytes;
		}
	}

	return 0;
}

static int iotest_write(struct dnet_node *n, void *data, size_t size, unsigned long long max, char *obj, int len, int num)
{
	struct dnet_io_control ctl;
	unsigned int *ptr = data;
	int first, last, err;

	ctl.aflags = 0;
	ctl.complete = iotest_complete;

	ctl.io.offset = 0;
	ctl.io.size = size;
	ctl.io.flags = DNET_IO_FLAGS_UPDATE;
	ctl.cmd = DNET_CMD_WRITE;

	ctl.data = data;
	ctl.fd = -1;

	first = 0;
	last = size / sizeof(int) - 1;

	while (max) {
		if (size > max)
			size = max;

		ptr[first] = ptr[last] = rand();

		ctl.priv = (void *)(unsigned long)size;
		err = dnet_write_object(n, &ctl, obj, len);
		if (err)
			return err;

		if (num) {
			err = dnet_lookup_object(n, ctl.io.id, dnet_lookup_complete, NULL);
			if (err)
				fprintf(stderr, "Failed to lookup a node for %s object.\n", dnet_dump_id(ctl.io.id));
			else
				num--;
		}

		max -= size;
		ctl.io.offset += size;
	}

	return 0;
}

static int iotest_read(struct dnet_node *n,void *data, size_t size, unsigned long long max, char *obj, int len __unused, int lookup_num)
{
	struct dnet_io_control ctl;
	int err, fd;
	struct dnet_io_attr *ios;
	char hfile[size + sizeof(DNET_HISTORY_SUFFIX) + 1];
	struct stat st;
	size_t  num;

	err = dnet_read_file(n, obj, 0, 0, 1);
	if (err)
		return err;

	snprintf(hfile, sizeof(hfile), "%s%s", obj, DNET_HISTORY_SUFFIX);

	fd = open(hfile, O_RDONLY);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "Failed to open history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_exit;
	}

	err = fstat(fd, &st);
	if (err) {
		err = -errno;
		fprintf(stderr, "Failed to stat history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_close;
	}

	ios = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ios == MAP_FAILED) {
		err = -errno;
		fprintf(stderr, "Failed to map history file '%s': %s.\n", hfile, strerror(errno));
		goto err_out_close;
	}

	ctl.aflags = 0;
	ctl.complete = iotest_complete;

	ctl.cmd = DNET_CMD_READ;

	ctl.data = data;
	ctl.fd = -1;

	num = st.st_size / sizeof(struct dnet_io_attr) - 1;

	while (max) {
		ctl.io = ios[(int)((double)(rand()) * num / (double) RAND_MAX)];

		dnet_convert_io_attr(&ctl.io);

		if (lookup_num) {
			err = dnet_lookup_object(n, ctl.io.id, dnet_lookup_complete, NULL);
			if (err)
				fprintf(stderr, "Failed to lookup a node for %s object.\n", dnet_dump_id(ctl.io.id));
			else
				lookup_num--;
		}

		memcpy(ctl.id, ctl.io.id, DNET_ID_SIZE);
		ctl.io.flags = 0;

		if (size > max)
			size = max;

		if (ctl.io.size > size)
			ctl.io.size = size;

		ctl.priv = (void *)(unsigned long)ctl.io.size;

		err = dnet_read_object(n, &ctl);
		if (err)
			return err;

		max -= size;
	}

	munmap(ios, st.st_size);
	close(fd);

	return 0;

err_out_close:
	close(fd);
err_out_exit:
	return err;
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

static void dnet_usage(char *p)
{
	fprintf(stderr, "Usage: %s\n"
			" -a addr:port:family  - creates a node with given network address\n"
			" -r addr:port:family  - adds a route to the given node\n"
			" -i object            - object name used to be transformed into ID\n"
			" -R                   - read write data from the network storage\n"
			" -T hash              - OpenSSL hash to use as a transformation function\n"
			" -l log               - log file. Default: stdout\n"
			" -w timeout           - wait timeout in seconds used to wait for content sync\n"
			" -m mask              - log events mask\n"
			" -s size              - chunk size used to wait for completion before starting the next one\n"
			" -S size              - amount of bytes transferred in the test\n"
			" -t seconds           - speed check interval\n"
			" -I id                - node ID\n"
			" -n num               - number of the server lookup requests sent during the test\n"
			, p);
}

int main(int argc, char *argv[])
{
	int trans_max = 5, trans_num = 0;
	int ch, err, i, have_remote = 0, write = 1;
	struct dnet_node *n = NULL;
	struct dnet_config cfg, rem;
	struct dnet_crypto_engine *e, *trans[trans_max];
	char *logfile = NULL, *obj = NULL;
	FILE *log = NULL;
	size_t size = 1024*1024;
	unsigned long long max = 100ULL * 1024 * 1024 * 1024;
	void *data;
	struct itimerval timer;
	int seconds = 1, num = 0;

	memset(&cfg, 0, sizeof(struct dnet_config));

	cfg.sock_type = SOCK_STREAM;
	cfg.proto = IPPROTO_TCP;
	cfg.wait_timeout = 60*60;
	cfg.log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;

	memcpy(&rem, &cfg, sizeof(struct dnet_config));

	while ((ch = getopt(argc, argv, "I:t:S:s:m:i:a:r:RT:l:w:h")) != -1) {
		switch (ch) {
			case 'n':
				num = atoi(optarg);
				break;
			case 'I':
				err = dnet_parse_numeric_id(optarg, cfg.id);
				if (err)
					return err;
				break;
			case 't':
				seconds = atoi(optarg);
				break;
			case 'S':
				max = strtoull(optarg, NULL, 0);
				break;
			case 's':
				size = strtoul(optarg, NULL, 0);
				break;
			case 'm':
				cfg.log_mask = strtoul(optarg, NULL, 0);
				break;
			case 'w':
				cfg.wait_timeout = atoi(optarg);
				break;
			case 'l':
				logfile = optarg;
				break;
			case 'i':
				obj = optarg;
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
			case 'R':
				write = 0;
				break;
			case 'T':
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

	if (!logfile)
		fprintf(stderr, "No log file found, logging will be disabled.\n");

	if (!have_remote) {
		fprintf(stderr, "No remote nodes to connect. Exiting.\n");
		return -1;
	}

	if (!obj) {
		fprintf(stderr, "No object name to use as ID.\n");
		return -1;
	}

	data = malloc(size);
	if (!data) {
		fprintf(stderr, "Failed to allocate %zu bytes for the data chunk.\n", size);
		return -1;
	}

	if (logfile) {
		log = fopen(logfile, "a");
		if (!log) {
			err = -errno;
			fprintf(stderr, "Failed to open log file %s: %s.\n", logfile, strerror(errno));
			return err;
		}

		cfg.log_private = log;
		cfg.log = dnet_example_log;
		cfg.log_append = dnet_example_log_append;
	}

	n = dnet_node_create(&cfg);
	if (!n)
		return -1;

	for (i=0; i<trans_num; ++i) {
		err = dnet_add_transform(n, trans[i], trans[i]->name,
				dnet_digest_init,
				dnet_digest_update,
				dnet_digest_final);
		if (err)
			return err;
	}

	err = dnet_add_state(n, &rem);
	if (err)
		return err;

	signal(SIGALRM, iotest_alarm);

	gettimeofday(&iotest_start, NULL);

	timer.it_interval.tv_sec = seconds;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec = seconds;
	timer.it_value.tv_usec = 0;

	err = setitimer(ITIMER_REAL, &timer, NULL);
	if (err)
		return err;
	
	srand(time(NULL));

	if (write)
		err = iotest_write(n, data, size, max, obj, strlen(obj), num);
	else
		err = iotest_read(n, data, size, max, obj, strlen(obj), num);

	printf("%s: size: %zu, max: %llu, obj: '%s', err: %d.\n", (write)?"Write":"Read", size, max, obj, err);

	if (err)
		return err;

	while (iotest_bytes < max)
		sleep(1);

	return 0;
}
