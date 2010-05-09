#define _GNU_SOURCE

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <alloca.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <fcgiapp.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "hash.h"
#include "common.h"
#include "backends.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define DNET_FCGI_ID_PATTERN		"id="
#define DNET_FCGI_ID_DELIMITER		"&"
#define DNET_FCGI_VERSION_PATTERN	"version="
#define DNET_FCGI_LOG			"/tmp/dnet_fcgi.log"
#define DNET_FCGI_LOCAL_ADDR		"0.0.0.0:1025:2"
#define DNET_FCGI_SUCCESS_STATUS_PATTERN	"Status: 301"
#define DNET_FCGI_ROOT_PATTERN		""
#define DNET_FCGI_MAX_REQUEST_SIZE	(100*1024*1024)
#define DNET_FCGI_COOKIE_HEADER		"HTTP_COOKIE"
#define DNET_FCGI_SIGN_HASH		"md5"
#define DNET_FCGI_RANDOM_FILE		"/dev/urandom"
#define DNET_FCGI_COOKIE_DELIMITER	"obscure_cookie="
#define DNET_FCGI_COOKIE_ENDING		";"
#define DNET_FCGI_TOKEN_STRING		" "
#define DNET_FCGI_TOKEN_HEADER_SPLIT_STRING		"|"
#define DNET_FCGI_TOKEN_DELIM		','
#define DNET_FCGI_STORAGE_BIT_NUM	8

static long dnet_fcgi_timeout_sec = 10;

static FILE *dnet_fcgi_log;
static pthread_cond_t dnet_fcgi_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dnet_fcgi_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int dnet_fcgi_request_completed, dnet_fcgi_request_init_value = 11223344, dnet_fcgi_request_error;
static char *dnet_fcgi_status_pattern, *dnet_fcgi_root_pattern;
static int dnet_fcgi_tolerate_upload_error_count;
static int dnet_fcgi_random_hashes;
static unsigned long dnet_fcgi_max_request_size;
static int dnet_fcgi_base_port;
static uint64_t dnet_fcgi_bit_num = DNET_FCGI_STORAGE_BIT_NUM;
static unsigned char dnet_fcgi_id[DNET_ID_SIZE];
static uint64_t dnet_fcgi_trans_tsec;

static char *dnet_fcgi_hashes;
static int dnet_fcgi_hashes_len;

static int dnet_fcgi_last_modified;

static char *dnet_fcgi_direct_download;
static int dnet_fcgi_direct_patterns_num;
static char **dnet_fcgi_direct_patterns;

static int dnet_fcgi_upload_host_limit;

/*
 * This is actually not a good idea, but it will work, since
 * no available crypto engines support that large digests.
 */
static char dnet_fcgi_sign_data[256];
static char dnet_fcgi_sign_tmp[4096];

/*
 * Freaking secure long lived key...
 */
static char *dnet_fcgi_sign_key;
static struct dnet_crypto_engine *dnet_fcgi_sign_hash;

static char *dnet_fcgi_cookie_header, *dnet_fcgi_cookie_delimiter, *dnet_fcgi_cookie_ending;
static int dnet_fcgi_cookie_delimiter_len;
static char *dnet_fcgi_cookie_addon;
static char *dnet_fcgi_cookie_key;
static long dnet_fcgi_expiration_interval;
static int dnet_urandom_fd;

static int dnet_fcgi_dns_lookup;

static char *dnet_fcgi_unlink_pattern;

#define DNET_FCGI_STAT_LOG		1
static int dnet_fcgi_stat_good, dnet_fcgi_stat_bad, dnet_fcgi_stat_bad_limit = -1;
static char *dnet_fcgi_stat_pattern, *dnet_fcgi_stat_log_pattern;

#define DNET_FCGI_EXTERNAL_CALLBACK_START	"dnet_fcgi_external_callback_start"
#define DNET_FCGI_EXTERNAL_CALLBACK_STOP	"dnet_fcgi_external_callback_stop"
#define DNET_FCGI_EXTERNAL_INIT			"dnet_fcgi_external_init"
#define DNET_FCGI_EXTERNAL_EXIT			"dnet_fcgi_external_exit"

static int (* dnet_fcgi_external_callback_start)(char *query, char *addr, char *id, int length);
static int (* dnet_fcgi_external_callback_stop)(char *query, char *addr, char *id, int length);
static void (* dnet_fcgi_external_exit)(void);

static FCGX_Request dnet_fcgi_request;

/*
 * This is a very weak protection, since data from one request can be sent to another client,
 * but it will only happen when we exit early on timeout, which should be noticed in logs, and
 * timeouts changed appropriately.
 *
 * It is set to 0 when dnet_fcgi_request is closed.
 */
static int dnet_fcgi_request_info;

static char **dnet_fcgi_pheaders;
static int dnet_fcgi_pheaders_num;

#define LISTENSOCK_FILENO	0
#define LISTENSOCK_FLAGS	0

struct dnet_fcgi_content_type {
	char	ext[16];
	char	type[32];
};
static int dnet_fcgi_ctypes_num;
static struct dnet_fcgi_content_type *dnet_fcgi_ctypes;

/*
 * Workaround for libfcgi 64bit issues, namely we will format
 * output here, since FCGX_FPrintF() resets the stream when sees
 * 64bit %llx or (seems so) %lx.
 */
static char dnet_fcgi_tmp_buf[40960];
static pthread_mutex_t dnet_fcgi_output_lock = PTHREAD_MUTEX_INITIALIZER;
static int dnet_fcgi_output(const char *format, ...) __attribute__ ((format(printf, 1, 2)));

static int dnet_fcgi_output(const char *format, ...)
{
	va_list args;
	int size, err = 0;
	char *ptr = dnet_fcgi_tmp_buf;

	va_start(args, format);
	pthread_mutex_lock(&dnet_fcgi_output_lock);
	if (!dnet_fcgi_request_info) {
		err = -EBADF;
		goto out_unlock;
	}

	size = vsnprintf(dnet_fcgi_tmp_buf, sizeof(dnet_fcgi_tmp_buf), format, args);
	while (size) {
		err = FCGX_PutStr(ptr, size, dnet_fcgi_request.out);
		if (err < 0 && errno != EAGAIN) {
			err = -errno;
			fprintf(dnet_fcgi_log, "Failed to output %d bytes: %s [%d].\n",
					size, strerror(errno), errno);
			break;
		}

		if (err > 0) {
			ptr += err;
			size -= err;
			err = 0;
		}
	}

out_unlock:
	pthread_mutex_unlock(&dnet_fcgi_output_lock);
	va_end(args);

	return err;
}

static int dnet_fcgi_fill_config(struct dnet_config *cfg)
{
	char *p;
	int err;
	char addr[128];

	memset(cfg, 0, sizeof(struct dnet_config));

	cfg->sock_type = SOCK_STREAM;
	cfg->proto = IPPROTO_TCP;
	cfg->wait_timeout = 60;
	cfg->log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	cfg->io_thread_num = 2;
	cfg->max_pending = 256;
	cfg->log = dnet_common_log;
	cfg->log_private = dnet_fcgi_log;
	cfg->log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;

	p = getenv("DNET_FCGI_NODE_ID");
	if (p) {
		err = dnet_parse_numeric_id(p, cfg->id);
		if (err)
			return err;
	}

	p = getenv("DNET_FCGI_NODE_LOG_MASK");
	if (p)
		cfg->log_mask = strtoul(p, NULL, 0);

	p = getenv("DNET_FCGI_NODE_WAIT_TIMEOUT");
	if (p)
		dnet_fcgi_timeout_sec = cfg->wait_timeout = strtoul(p, NULL, 0);

	p = getenv("DNET_FCGI_NODE_LOCAL_ADDR");
	if (!p)
		p = DNET_FCGI_LOCAL_ADDR;

	snprintf(addr, sizeof(addr), "%s", p);

	err = dnet_parse_addr(addr, cfg);
	if (err)
		return err;

	return 0;
}

static int dnet_fcgi_add_remote_addr(struct dnet_node *n, struct dnet_config *main_cfg)
{
	char *a;
	char *addr, *p;
	int added = 0, err;
	struct dnet_config cfg;

	addr = getenv("DNET_FCGI_REMOTE_ADDR");
	if (!addr) {
		fprintf(dnet_fcgi_log, "No remote address specified, aborting.\n");
		err = -ENOENT;
		goto err_out_exit;
	}

	a = strdup(addr);
	if (!a) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	addr = a;

	while (addr) {
		p = strchr(addr, ' ');
		if (p)
			*p++ = '\0';

		memcpy(&cfg, main_cfg, sizeof(struct dnet_config));

		err = dnet_parse_addr(addr, &cfg);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to parse addr '%s': %d.\n", addr, err);
			goto next;
		}

		err = dnet_add_state(n, &cfg);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to add addr '%s': %d.\n", addr, err);
			goto next;
		}

		added++;

		if (!p)
			break;

next:
		addr = p;

		while (addr && *addr && isspace(*addr))
			addr++;
	}

	free(a);

	if (!added) {
		err = -ENOENT;
		fprintf(dnet_fcgi_log, "No remote addresses added, aborting.\n");
		goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

static int dnet_fcgi_add_transform(struct dnet_node *n)
{
	char *h = NULL, *hash, *p;
	int added = 0, err;
	struct dnet_crypto_engine *e;

	hash = getenv("DNET_FCGI_HASH");
	if (!hash) {
		fprintf(dnet_fcgi_log, "No hashes specified, aborting.\n");
		err = -ENODEV;
		goto err_out_exit;
	}

	dnet_fcgi_hashes = strdup(hash);
	if (!dnet_fcgi_hashes) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	dnet_fcgi_hashes_len = strlen(dnet_fcgi_hashes);

	h = strdup(hash);
	if (!h) {
		err = -ENOMEM;
		goto err_out_free;
	}

	hash = h;

	while (hash) {
		p = strchr(hash, ' ');
		if (p)
			*p++ = '\0';

		e = malloc(sizeof(struct dnet_crypto_engine));
		if (!e) {
			err = -ENOMEM;
			goto err_out_free;
		}

		memset(e, 0, sizeof(struct dnet_crypto_engine));

		err = dnet_crypto_engine_init(e, hash);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to initialize hash '%s': %d.\n",
					hash, err);
			goto err_out_free;
		}

		err = dnet_add_transform(n, e, e->name,	e->init, e->update, e->final, e->cleanup);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to add hash '%s': %d.\n", hash, err);
			goto err_out_free;
		}

		fprintf(dnet_fcgi_log, "Added hash '%s'.\n", hash);
		added++;

		if (!p)
			break;

		hash = p;

		while (hash && *hash && isspace(*hash))
			hash++;
	}

	if (!added) {
		err = -ENOENT;
		fprintf(dnet_fcgi_log, "No remote hashes added, aborting.\n");
		goto err_out_free;
	}

	free(h);

	return 0;

err_out_free:
	free(dnet_fcgi_hashes);
	dnet_fcgi_hashes_len = 0;
	free(h);
err_out_exit:
	return err;
}

#define dnet_fcgi_wait(condition, wts)							\
({											\
	int _err = 0;									\
	struct timespec _ts;								\
 	struct timeval _tv;								\
	gettimeofday(&_tv, NULL);							\
	_ts.tv_nsec = _tv.tv_usec * 1000 + (wts)->tv_nsec;				\
	_ts.tv_sec = _tv.tv_sec + (wts)->tv_sec;						\
	pthread_mutex_lock(&dnet_fcgi_wait_lock);					\
	while (!(condition) && !_err)							\
		_err = pthread_cond_timedwait(&dnet_fcgi_cond, &dnet_fcgi_wait_lock, &_ts);		\
	pthread_mutex_unlock(&dnet_fcgi_wait_lock);					\
	-_err;										\
})

#define dnet_fcgi_wakeup(doit)						\
({										\
 	int ______ret;								\
	pthread_mutex_lock(&dnet_fcgi_wait_lock);				\
 	______ret = (doit);							\
	pthread_cond_broadcast(&dnet_fcgi_cond);					\
	pthread_mutex_unlock(&dnet_fcgi_wait_lock);				\
 	______ret;								\
})

static void dnet_fcgi_data_to_hex(char *dst, unsigned int dlen, unsigned char *src, unsigned int slen)
{
	unsigned int i;

	if (slen > dlen/2 - 1)
		slen = dlen/2 - 1;

	for (i=0; i<slen; ++i)
		sprintf(&dst[2*i], "%02x", src[i]);
}

static int dnet_fcgi_generate_sign(long timestamp)
{
	char *cookie = FCGX_GetParam(dnet_fcgi_cookie_header, dnet_fcgi_request.envp);
	struct dnet_crypto_engine *e = dnet_fcgi_sign_hash;
	int err, len;
	char cookie_res[256];
	unsigned int rsize = sizeof(dnet_fcgi_sign_data);

	if (cookie) {
		char *val, *end;

		val = strstr(cookie, dnet_fcgi_cookie_delimiter);

		if (!val || ((signed)strlen(cookie) <= dnet_fcgi_cookie_delimiter_len)) {
			fprintf(dnet_fcgi_log, "wrong cookie '%s', generating new one.\n", cookie);
			cookie = NULL;
		} else {
			val += dnet_fcgi_cookie_delimiter_len;

			end = strstr(val, dnet_fcgi_cookie_ending);
			if (end)
				len = end - val + 1; /* including NULL byte */
			else
				len = sizeof(cookie_res);

			if (len > (int)sizeof(cookie_res))
				len = sizeof(cookie_res);

			snprintf(cookie_res, len, "%s", val);
			cookie = cookie_res;
		}
	}

	if (!cookie) {
		uint32_t tmp;

		err = read(dnet_urandom_fd, &tmp, sizeof(tmp));
		if (err < 0) {
			err = -errno;
			fprintf(dnet_fcgi_log, "Failed to read random data: %s [%d].\n",
					strerror(errno), errno);
			goto err_out_exit;
		}

		cookie = dnet_fcgi_sign_tmp;
		len = snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%s%x%lx", dnet_fcgi_cookie_key, tmp, timestamp);

		e->init(e, NULL);
		e->update(e, dnet_fcgi_sign_tmp, len, dnet_fcgi_sign_data, &rsize, 0);
		e->final(e, dnet_fcgi_sign_data, dnet_fcgi_sign_data, &rsize, 0);

		dnet_fcgi_data_to_hex(cookie_res, sizeof(cookie_res), (unsigned char *)dnet_fcgi_sign_data, rsize);
		snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%x.%lx.%s", tmp, timestamp, cookie_res);

		fprintf(dnet_fcgi_log, "Cookie generation: '%s' [%d bytes] -> '%s' : '%s%s'\n",
				dnet_fcgi_sign_tmp, len, cookie_res,
				dnet_fcgi_cookie_delimiter, dnet_fcgi_sign_tmp);

		dnet_fcgi_output("Set-Cookie: %s%s",
				dnet_fcgi_cookie_delimiter, dnet_fcgi_sign_tmp);
		if (dnet_fcgi_expiration_interval) {
			char str[128];
			struct tm tm;
			time_t t = timestamp + dnet_fcgi_expiration_interval;

			localtime_r(&t, &tm);
			strftime(str, sizeof(str), "%a, %d-%b-%Y %T %Z", &tm);
			dnet_fcgi_output("%s expires=%s%s",
					dnet_fcgi_cookie_ending, str, dnet_fcgi_cookie_addon);
		}
		dnet_fcgi_output("\r\n");

		snprintf(cookie_res, sizeof(cookie_res), "%s", dnet_fcgi_sign_tmp);
	}

	err = 0;
	len = snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%s%lx%s", dnet_fcgi_sign_key, timestamp, cookie_res);

	rsize = sizeof(dnet_fcgi_sign_data);
	e->init(e, NULL);
	e->update(e, dnet_fcgi_sign_tmp, len, dnet_fcgi_sign_data, &rsize, 0);
	e->final(e, dnet_fcgi_sign_data, dnet_fcgi_sign_data, &rsize, 0);

	dnet_fcgi_data_to_hex(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), (unsigned char *)dnet_fcgi_sign_data, rsize);

	fprintf(dnet_fcgi_log, "Sign generation: '%s%lx%s' [%d bytes] -> '%s'\n",
			dnet_fcgi_sign_key, timestamp, cookie_res, len, dnet_fcgi_sign_tmp);

err_out_exit:
	return err;
}

static int dnet_fcgi_put_last_modified()
{
	char str[128];
	char fmt[] = "%a, %d %b %Y %T %Z";
	struct tm tm;
	char *p;

	if (!dnet_fcgi_last_modified)
		return 0;

	p = FCGX_GetParam("HTTP_IF_MODIFIED_SINCE", dnet_fcgi_request.envp);
	if (p) {
		p = strptime(p, fmt, &tm);
		if (p) {
			uint64_t t = timegm(&tm);

			if (dnet_fcgi_trans_tsec <= t) {
				dnet_fcgi_output("Status: 304\r\n\r\n");
				return 1;
			}
		}
	}

	gmtime_r((time_t *)&dnet_fcgi_trans_tsec, &tm);
	strftime(str, sizeof(str), fmt, &tm);
	dnet_fcgi_output("Last-Modified: %s\r\n", str);

	return 0;
}

static int dnet_fcgi_lookup_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr, void *priv)
{
	int err = 0;
	struct dnet_addr_attr *a;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		err = dnet_lookup_complete(st, cmd, attr, priv);
		if (err && err != -EEXIST)
			goto err_out_exit;

		a = (struct dnet_addr_attr *)(attr + 1);
#if 1
		fprintf(dnet_fcgi_log, "%s: addr: %s, is object presented there: %d.\n",
				dnet_dump_id(cmd->id),
				dnet_server_convert_dnet_addr(&a->addr),
				attr->flags);
#endif
		err = -ENOENT;
		if (attr->flags) {
			char addr[256];
			char id[DNET_ID_SIZE*2+1];
			int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);
			long timestamp = time(NULL);
			char hex_dir[2*DNET_ID_SIZE+1];

			snprintf(id, sizeof(id), "%s", dnet_dump_id_len(dnet_fcgi_id, DNET_ID_SIZE));
			file_backend_get_dir(dnet_fcgi_id, dnet_fcgi_bit_num, hex_dir);

			if (dnet_fcgi_dns_lookup) {
				err = getnameinfo((struct sockaddr *)a->addr.addr, a->addr.addr_len,
						addr, sizeof(addr), NULL, 0, 0);
				if (err)
					snprintf(addr, sizeof(addr), "%s", dnet_state_dump_addr_only(&a->addr));
			} else {
				snprintf(addr, sizeof(addr), "%s", dnet_state_dump_addr_only(&a->addr));
			}
#if 1
			fprintf(dnet_fcgi_log, "%s -> http://%s%s/%d/%s/%s...\n",
					dnet_fcgi_status_pattern,
					addr,
					dnet_fcgi_root_pattern, port - dnet_fcgi_base_port,
					hex_dir, id);
#endif
			err = dnet_fcgi_put_last_modified();
			if (err) {
				if (err > 0)
					err = 0;
				goto err_out_exit;
			}

			dnet_fcgi_output("%s\r\n", dnet_fcgi_status_pattern);
			if (!dnet_fcgi_last_modified)
				dnet_fcgi_output("Cache-control: no-cache\r\n");
			dnet_fcgi_output("Location: http://%s%s/%d/%s/%s\r\n",
					addr,
					dnet_fcgi_root_pattern,
					port - dnet_fcgi_base_port,
					hex_dir,
					id);

			/*
			 * Race lives here - multiple threads can simultaneously
			 * use shared sign/cookie buffers.
			 * But we are safe until lookup is called in parallel.
			 */
			if (dnet_fcgi_sign_key) {
				err = dnet_fcgi_generate_sign(timestamp);
				if (err)
					goto err_out_exit;
			}

			dnet_fcgi_output("Content-type: application/xml\r\n\r\n");

			dnet_fcgi_output("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
					"<download-info><host>%s</host><path>%s/%d/%s/%s</path><ts>%lx</ts>",
					addr,
					dnet_fcgi_root_pattern, port - dnet_fcgi_base_port,
					hex_dir,
					id,
					timestamp);

			if (dnet_fcgi_sign_key)
				dnet_fcgi_output("<s>%s</s>", dnet_fcgi_sign_tmp);
			dnet_fcgi_output("</download-info>\r\n");

			err = 0;
		}

		dnet_fcgi_wakeup(dnet_fcgi_request_completed = err);
	}

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	return err;

err_out_exit:
	if (!cmd || !(cmd->flags & DNET_FLAGS_MORE))
		dnet_fcgi_wakeup(dnet_fcgi_request_completed = err);
	return err;
}

static int dnet_fcgi_unlink_complete(struct dnet_net_state *st __unused,
		struct dnet_cmd *cmd, struct dnet_attr *a __unused,
		void *priv __unused)
{
	if (!cmd || !(cmd->flags & DNET_FLAGS_MORE))
		dnet_fcgi_wakeup(dnet_fcgi_request_completed++);
	return 0;
}

static int dnet_fcgi_get_data_version_id(struct dnet_node *n, unsigned char *id, unsigned char *dst,
		uint64_t *tsec, int version, int unlink_upload)
{
	char file[32 + 5 + 1 + 2*DNET_ID_SIZE + sizeof(DNET_HISTORY_SUFFIX)]; /* 32 is for pid length */
	struct dnet_history_map m;
	struct dnet_history_entry *e;
	int err, stored_version;
	long i;

	snprintf(file, sizeof(file), "/tmp/%s-%d", dnet_dump_id_len(id, DNET_ID_SIZE), getpid());

	err = dnet_read_file(n, file, file, strlen(file), id, 0, 0, 1);
	if (err < 0)
		goto err_out_exit;

	strcat(file, DNET_HISTORY_SUFFIX);

	err = dnet_map_history(n, file, &m);
	if (err)
		goto err_out_unlink;

	err = -ENOENT;
	for (i=m.num-1; i>=0; --i) {
		e = &m.ent[i];

		memcpy(&stored_version, &e->id[4], 4);

		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: stored: %d, version: %d, deleted: %d.\n",
				dnet_dump_id(e->id), stored_version, version, !!e->flags);

		if (stored_version <= version) {
			dnet_convert_history_entry(e);
			/* If requested version was removed we have to return error */
			if (e->flags)
				i = -1;
			break;
		}
	}

	if (i >= 0) {
		if (dst)
			memcpy(dst, e->id, DNET_ID_SIZE);
		err = 0;

		if (tsec)
			*tsec = e->tsec;

		if (unlink_upload) {
			e->flags |= DNET_HISTORY_FLAGS_REMOVE;
			dnet_convert_history_entry(e);

			err = dnet_write_file_local_offset(n, file, file, strlen(file), id, 0, 0, 0,
					DNET_ATTR_NO_TRANSACTION_SPLIT | DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY);
		}
	}

	dnet_unmap_history(n, &m);
err_out_unlink:
	unlink(file);
err_out_exit:
	return err;
}

static int dnet_fcgi_unlink_version(struct dnet_node *n, struct dnet_trans_control *ctl, int version)
{
	int err;

	err = dnet_fcgi_get_data_version_id(n, dnet_fcgi_id, ctl->id, NULL, version, 1);
	if (err)
		return err;

	return dnet_trans_alloc_send(n, ctl);
}

static int dnet_fcgi_unlink(struct dnet_node *n, char *obj, int len, int version)
{
	unsigned char addr[DNET_ID_SIZE];
	int err, error = -ENOENT;
	int pos = 0, num = 0;
	struct dnet_trans_control ctl;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	fprintf(dnet_fcgi_log, "Unlinking object '%s', version: %d.\n", obj, version);

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.complete = dnet_fcgi_unlink_complete;
	ctl.cmd = DNET_CMD_DEL;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = DNET_ATTR_DIRECT_TRANSACTION;

	dnet_fcgi_request_completed = 0;
	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, obj, len, dnet_fcgi_id, addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		memcpy(ctl.id, dnet_fcgi_id, DNET_ID_SIZE);

		if (version == -1) {
			err = dnet_trans_alloc_send(n, &ctl);
		} else {
			err = dnet_fcgi_unlink_version(n, &ctl, version);
		}

		if (err)
			error = err;
		else
			error = 0;

		num++;
	}

	err = dnet_fcgi_wait(dnet_fcgi_request_completed == num, &ts);
	if (err) {
		fprintf(dnet_fcgi_log, "Failed to wait for removal completion of '%s' object.\n", obj);
		error = err;
	}
	return error;
}

static int dnet_fcgi_get_data(struct dnet_node *n, unsigned char *id, struct dnet_io_control *ctl, uint64_t *tsec)
{
	int err;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	if (dnet_fcgi_last_modified) {
		uint64_t tsec_local;

		err = 0;
		if (!tsec) {
			tsec = &tsec_local;
			err = dnet_fcgi_get_data_version_id(n, id, NULL, tsec, INT_MAX, 0);
			if (err)
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to get last timestamp: %d.\n", dnet_dump_id(id), err);
		}

		dnet_fcgi_trans_tsec = *tsec;
	}

	dnet_fcgi_request_completed = dnet_fcgi_request_init_value;

	if (ctl) {
		memcpy(ctl->io.id, id, DNET_ID_SIZE);
		memcpy(ctl->io.origin, id, DNET_ID_SIZE);
		memcpy(ctl->addr, id, DNET_ID_SIZE);

		err = dnet_read_object(n, ctl);
	} else {
		memcpy(dnet_fcgi_id, id, DNET_ID_SIZE);
		err = dnet_lookup_object(n, id, DNET_ATTR_LOOKUP_STAT,
				dnet_fcgi_lookup_complete, NULL);
	}

	if (err)
		goto err_out_exit;

	err = dnet_fcgi_wait(dnet_fcgi_request_completed != dnet_fcgi_request_init_value, &ts);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: IO wait completion failed: %d.\n", id, err);
		goto err_out_exit;
	}

	if (dnet_fcgi_request_completed < 0) {
		err = dnet_fcgi_request_completed;
		goto err_out_exit;
	}

	err = 0;

err_out_exit:
	return err;
}

static int dnet_fcgi_get_data_version(struct dnet_node *n, unsigned char *id, struct dnet_io_control *ctl, int version)
{
	int err;
	unsigned char dst[DNET_ID_SIZE];
	uint64_t tsec;

	err = dnet_fcgi_get_data_version_id(n, id, dst, &tsec, version, 0);
	if (err)
		return err;

	return dnet_fcgi_get_data(n, dst, ctl, &tsec);
}

static int dnet_fcgi_process_io(struct dnet_node *n, char *obj, int len, struct dnet_io_control *ctl, int version)
{
	unsigned char addr[DNET_ID_SIZE];
	int err, error = -ENOENT;
	int pos = 0, random_num = 0;
	int *random_pos = NULL;

	if (dnet_fcgi_random_hashes) {
		int i;

		random_pos = alloca(sizeof(int) * dnet_fcgi_random_hashes);
		for (i=0; i<dnet_fcgi_random_hashes; ++i)
			random_pos[i] = i;
	}

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		if (dnet_fcgi_random_hashes) {
			if (random_num < dnet_fcgi_random_hashes) {
				int r;

				r = rand() * (dnet_fcgi_random_hashes - random_num - 1) / RAND_MAX;

				pos = random_pos[r];
				dnet_log_raw(n, DNET_LOG_NOTICE, "Using r: %d, pos: %d/%d.\n", r, pos, dnet_fcgi_random_hashes);

				for (; r<dnet_fcgi_random_hashes-1; r++)
					random_pos[r] = random_pos[r+1];

				random_num++;
			}
		}

#if 1
		err = dnet_transform(n, obj, len, dnet_fcgi_id, addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}
#else
		if (!pos) {
			char val[2*DNET_ID_SIZE+1];

			snprintf(val, sizeof(val), "%s", obj);
			if (len < (signed)sizeof(val) - 1)
				val[len] = '\0';
			
			dnet_parse_numeric_id(val, addr);
			memcpy(dnet_fcgi_id, addr, DNET_ID_SIZE);
			rsize = DNET_ID_SIZE;
			pos++;
		}
#endif

		if (version == -1) {
			err = dnet_fcgi_get_data(n, dnet_fcgi_id, ctl, NULL);
		} else {
			err = dnet_fcgi_get_data_version(n, dnet_fcgi_id, ctl, version);
		}

		if (err) {
			error = err;
			continue;
		}

		error = 0;
		break;
	}

	return error;
}

static int dnet_fcgi_upload_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv __unused)
{
	int err = 0;
	char id[DNET_ID_SIZE*2+1];

	if (!cmd || !st) {
		err = -EINVAL;
		goto out_wakeup;
	}

	if (cmd->status)
		err = cmd->status;

	if (cmd->flags & DNET_FLAGS_MORE)
		return err;

out_wakeup:
	fprintf(dnet_fcgi_log, "%s: upload completed: %d, err: %d.\n",
			dnet_dump_id(cmd->id), dnet_fcgi_request_completed, err);
	dnet_fcgi_output("<complete><id>%s</id><status>%d</status></complete>", dnet_dump_id_len_raw(cmd->id, DNET_ID_SIZE, id), err);
	dnet_fcgi_wakeup({ do { dnet_fcgi_request_completed++; if (err) dnet_fcgi_request_error++; } while (0); -1; });
	return err;
}

static int dnet_fcgi_send_upload_transactions(struct dnet_node *n, struct dnet_io_control *ctl)
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

static void dnet_fcgi_convert_id_version(unsigned char *id, int version)
{
	memcpy(id+4, &version, 4);
}

static int dnet_fcgi_send_meta_transactions(struct dnet_node *n, char *obj, int len)
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
	m.size = dnet_fcgi_hashes_len + 1; /* 0-byte */

	err = dnet_meta_create_file(n, file, &m, dnet_fcgi_hashes);
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

static int dnet_fcgi_write_object(struct dnet_node *n, char *obj, unsigned int len, void *data, uint64_t size, int version, int pos)
{
	struct dnet_io_control ctl;
	int old_pos = pos, err;
	unsigned int rsize;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = data;
	ctl.fd = -1;

	ctl.complete = dnet_fcgi_upload_complete;
	ctl.priv = NULL;

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

		dnet_fcgi_convert_id_version(ctl.io.origin, version);
		dnet_fcgi_convert_id_version(ctl.addr, version);

		ctl.io.flags |= DNET_IO_FLAGS_ID_VERSION | DNET_IO_FLAGS_ID_CONTENT;
	} else {
		ctl.aflags |= DNET_ATTR_DIRECT_TRANSACTION;
		memcpy(ctl.io.origin, ctl.io.id, DNET_ID_SIZE);
	}

	err = dnet_fcgi_send_upload_transactions(n, &ctl);
	if (err <= 0)
		goto out_exit;
	return err;

out_exit:
	if (err > 0 || pos == old_pos)
		return 0;
	return err;
}

static int dnet_fcgi_upload(struct dnet_node *n, char *obj, unsigned int len,
		void *data, uint64_t size, int version)
{
	int trans_num = 0, pos = 0;
	int err;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	dnet_fcgi_output("Content-type: application/xml\r\n\r\n");
	dnet_fcgi_output("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
	dnet_fcgi_output("<post object=\"%s\">", obj);

	dnet_fcgi_request_error = 0;
	dnet_fcgi_request_completed = 0;

	while (1) {
		err = dnet_fcgi_write_object(n, obj, len, data, size, version, pos);
		if (err <= 0)
			break;

		trans_num += err;
		pos++;
	}
	if (trans_num)
		dnet_fcgi_send_meta_transactions(n, obj, len);

	fprintf(dnet_fcgi_log, "Waiting for upload completion: %d/%d.\n", dnet_fcgi_request_completed, trans_num);
	err = dnet_fcgi_wait(dnet_fcgi_request_completed == trans_num, &ts);
	dnet_fcgi_output("</post>\r\n");

	if (!err && dnet_fcgi_request_error > dnet_fcgi_tolerate_upload_error_count)
		err = -ENOENT;
	if (err)
		dnet_log_raw(n, DNET_LOG_ERROR, "Upload failed: obj: '%s', "
				"err: %d, request_error: %d, tolerate_error_count: %d.\n",
				obj, err, dnet_fcgi_request_error, dnet_fcgi_tolerate_upload_error_count);

	return err;
}

static int dnet_fcgi_handle_post(struct dnet_node *n, char *addr, char *id, int length, int version)
{
	void *data;
	unsigned long data_size, size;
	char *p;
	long err;

	if (dnet_fcgi_upload_host_limit) {
		int num = dnet_state_num(n);

		if (num < dnet_fcgi_upload_host_limit) {
			fprintf(dnet_fcgi_log, "Number of connected states (%d) is less than allowed in config for post (%d).\n",
				num, dnet_fcgi_upload_host_limit);
			return -ENOTCONN;
		}
	}

	p = FCGX_GetParam("CONTENT_LENGTH", dnet_fcgi_request.envp);
	if (!p) {
		fprintf(dnet_fcgi_log, "%s: no content length.\n", addr);
		goto err_out_exit;
	}

	data_size = strtoul(p, NULL, 0);
	if (data_size > dnet_fcgi_max_request_size || !data_size) {
		fprintf(dnet_fcgi_log, "%s: invalid content length: %lu.\n", addr, data_size);
		goto err_out_exit;
	}

	data = malloc(data_size);
	if (!data) {
		fprintf(dnet_fcgi_log, "%s: failed to allocate %lu bytes.\n", addr, data_size);
		goto err_out_exit;
	}

	size = data_size;
	p = data;

	while (size) {
		err = FCGX_GetStr(p, size, dnet_fcgi_request.in);
		if (err < 0 && errno != EAGAIN) {
			fprintf(dnet_fcgi_log, "%s: failed to read %lu bytes, total of %lu: %s [%d].\n",
					addr, size, data_size, strerror(errno), errno);
			goto err_out_free;
		}

		if (err == 0) {
			fprintf(dnet_fcgi_log, "%s: short read, %lu/%lu, aborting.\n",
					addr, size, data_size);
			goto err_out_free;
		}

		p += err;
		size -= err;
	}

	err = dnet_fcgi_upload(n, id, length, data, data_size, version);
	if (err)
		goto err_out_free;

	free(data);

	return 0;

err_out_free:
	free(data);
err_out_exit:
	return -EINVAL;
}

static void dnet_fcgi_destroy_sign_hash(void)
{
	if (!dnet_fcgi_sign_key)
		return;

	close(dnet_urandom_fd);
}

static int dnet_fcgi_setup_sign_hash(void)
{
	char *p;
	int err = -ENOMEM;

	dnet_fcgi_sign_key = getenv("DNET_FCGI_SIGN_KEY");
	if (!dnet_fcgi_sign_key) {
		err = 0;
		fprintf(dnet_fcgi_log, "No sign key, system will not authentificate users.\n");
		goto err_out_exit;
	}

	p = getenv("DNET_FCGI_SIGN_HASH");
	if (!p)
		p = DNET_FCGI_SIGN_HASH;

	dnet_fcgi_sign_hash = malloc(sizeof(struct dnet_crypto_engine));
	if (!dnet_fcgi_sign_hash)
		goto err_out_exit;

	err = dnet_crypto_engine_init(dnet_fcgi_sign_hash, p);
	if (err) {
		fprintf(dnet_fcgi_log, "Failed to initialize hash '%s': %d.\n", p, err);
		goto err_out_free;
	}

	p = getenv("DNET_FCGI_RANDOM_FILE");
	if (!p)
		p = DNET_FCGI_RANDOM_FILE;
	err = open(p, O_RDONLY);
	if (err < 0) {
		err = -errno;
		fprintf(dnet_fcgi_log, "Failed to open (read-only) random file '%s': %s [%d].\n",
				p, strerror(errno), errno);
		goto err_out_destroy;
	}
	dnet_urandom_fd  = err;

	dnet_fcgi_cookie_header = getenv("DNET_FCGI_COOKIE_HEADER");
	if (!dnet_fcgi_cookie_header)
		dnet_fcgi_cookie_header = DNET_FCGI_COOKIE_HEADER;

	dnet_fcgi_cookie_key = getenv("DNET_FCGI_COOKIE_KEY");
	if (!dnet_fcgi_cookie_key)
		dnet_fcgi_cookie_key = "";

	dnet_fcgi_cookie_addon = getenv("DNET_FCGI_COOKIE_ADDON");
	if (!dnet_fcgi_cookie_addon)
		dnet_fcgi_cookie_addon = "";

	dnet_fcgi_cookie_delimiter = getenv("DNET_FCGI_COOKIE_DELIMITER");
	if (!dnet_fcgi_cookie_delimiter)
		dnet_fcgi_cookie_delimiter = DNET_FCGI_COOKIE_DELIMITER;
	dnet_fcgi_cookie_delimiter_len = strlen(dnet_fcgi_cookie_delimiter);

	dnet_fcgi_cookie_ending = getenv("DNET_FCGI_COOKIE_ENDING");
	if (!dnet_fcgi_cookie_ending)
		dnet_fcgi_cookie_ending = DNET_FCGI_COOKIE_ENDING;

	p = getenv("DNET_FCGI_COOKIE_EXPIRATION_INTERVAL");
	if (p)
		dnet_fcgi_expiration_interval = atoi(p);

	return 0;

err_out_destroy:
	dnet_fcgi_sign_hash->cleanup(dnet_fcgi_sign_hash);
	dnet_fcgi_sign_hash = NULL;
err_out_free:
	free(dnet_fcgi_sign_hash);
err_out_exit:
	dnet_fcgi_sign_key = NULL;
	return err;
}

static int dnet_fcgi_read_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *a, void *priv __unused)
{
	int err;
	struct dnet_io_attr *io;
	unsigned long long size;
	void *data;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		fprintf(dnet_fcgi_log, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		fprintf(dnet_fcgi_log, "%s: no attributes but command size is not null.\n", dnet_dump_id(cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	err = dnet_fcgi_put_last_modified();
	if (err) {
		if (err > 0)
			err = 0;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(a + 1);
	data = io + 1;

	dnet_convert_io_attr(io);

	dnet_fcgi_output("\r\n");

	size = io->size;

	pthread_mutex_lock(&dnet_fcgi_output_lock);

	if (!dnet_fcgi_request_info) {
		err = -EBADF;
		goto err_out_unlock;
	}

	while (size) {
		err = FCGX_PutStr(data, size, dnet_fcgi_request.out);
		if (err < 0 && errno != EAGAIN) {
			err = -errno;
			fprintf(dnet_fcgi_log, "%s: failed to write %llu bytes, "
					"total of %llu: %s [%d].\n",
					dnet_dump_id(dnet_fcgi_id), size, (unsigned long long)io->size,
					strerror(errno), errno);
			goto err_out_unlock;
		}

		if (err > 0) {
			data += err;
			size -= err;
		}
	}

	err = 0;

err_out_unlock:
	pthread_mutex_unlock(&dnet_fcgi_output_lock);
err_out_exit:
	if (!cmd || !(cmd->flags & DNET_FLAGS_MORE))
		dnet_fcgi_wakeup(dnet_fcgi_request_completed = err);
	return err;
}

static int dnet_fcgi_stat_complete(struct dnet_net_state *state,
	struct dnet_cmd *cmd, struct dnet_attr *attr __unused, void *priv __unused)
{
	if (!state || !cmd || cmd->status) {
		if (cmd)
			fprintf(dnet_fcgi_log, "state: %p, cmd: %p, err: %d.\n", state, cmd, cmd->status);
		dnet_fcgi_stat_bad++;
		goto out_wakeup;
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		dnet_fcgi_stat_good++;
		goto out_wakeup;
	}

	return 0;

out_wakeup:
	dnet_fcgi_wakeup(dnet_fcgi_request_completed++);
	return 0;
}

static int dnet_fcgi_stat_complete_log(struct dnet_net_state *state,
	struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	if (state && cmd && attr && attr->size == sizeof(struct dnet_stat)) {
		float la[3];
		struct dnet_stat *st;
		char id[DNET_ID_SIZE * 2 + 1];
		char addr[128];

		st = (struct dnet_stat *)(attr + 1);

		dnet_convert_stat(st);

		la[0] = (float)st->la[0] / 100.0;
		la[1] = (float)st->la[1] / 100.0;
		la[2] = (float)st->la[2] / 100.0;

		dnet_fcgi_output("<stat addr=\"%s\" id=\"%s\"><la>%.2f %.2f %.2f</la>"
				"<memtotal>%llu KB</memtotal><memfree>%llu KB</memfree><memcached>%llu KB</memcached>"
				"<storage_size>%llu MB</storage_size><available_size>%llu MB</available_size>"
				"<files>%llu</files><fsid>0x%llx</fsid></stat>",
				dnet_server_convert_dnet_addr_raw(dnet_state_addr(state), addr, sizeof(addr)),
				dnet_dump_id_len_raw(cmd->id, DNET_ID_SIZE, id),
				la[0], la[1], la[2],
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached,
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
	}

	return dnet_fcgi_stat_complete(state, cmd, attr, priv);
}

static int dnet_fcgi_request_stat(struct dnet_node *n,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv))
{
	int err, num;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	dnet_fcgi_stat_good = dnet_fcgi_stat_bad = 0;
	dnet_fcgi_request_completed = 0;

	num = err = dnet_request_stat(n, NULL, complete, NULL);
	if (err < 0) {
		fprintf(dnet_fcgi_log, "Failed to request stat: %d.\n", err);
		goto err_out_exit;
	}

	err = dnet_fcgi_wait(num == dnet_fcgi_request_completed, &ts);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Statistics request wait completion failed: "
				"%d, num: %d, completed: %d.\n", err, num, dnet_fcgi_request_completed);
	}
err_out_exit:
	return err;
}

static int dnet_fcgi_stat_log(struct dnet_node *n)
{
	int err;

	dnet_fcgi_output("Content-type: application/xml\r\n");
	dnet_fcgi_output("%s\r\n\r\n", dnet_fcgi_status_pattern);
	dnet_fcgi_output("<?xml version=\"1.0\" encoding=\"utf-8\"?><data>");

	err = dnet_fcgi_request_stat(n, dnet_fcgi_stat_complete_log);

	dnet_fcgi_output("</data>");

	return err;
}

static int dnet_fcgi_stat(struct dnet_node *n)
{
	int err = dnet_fcgi_request_stat(n, dnet_fcgi_stat_complete);

	if (	err ||
		((dnet_fcgi_stat_bad_limit == -1) && (dnet_fcgi_stat_bad > dnet_fcgi_stat_good)) ||
		((dnet_fcgi_stat_bad_limit >= 0) && (dnet_fcgi_stat_bad > dnet_fcgi_stat_bad_limit)) ||
		((dnet_fcgi_stat_bad_limit >= 0) && (dnet_fcgi_stat_good < dnet_fcgi_stat_bad_limit)))
			err = -1;

	if (err)
		dnet_fcgi_output("\r\nStatus: 400\r\n\r\n");
	else
		dnet_fcgi_output("\r\n%s\r\n\r\n", dnet_fcgi_status_pattern);

	return err;
}

static int dnet_fcgi_external_raw(struct dnet_node *n, char *query, char *addr, char *id, int length, int tail)
{
	int err, region;
	char trans[32], *hash, *h, *p;

	err = dnet_fcgi_external_callback_start(query, addr, id, length);
	if (err < 0)
		return err;

	region = err;

	hash = getenv("DNET_FCGI_HASH");
	if (!hash) {
		fprintf(dnet_fcgi_log, "No hashes specified, aborting.\n");
		err = -ENODEV;
		goto err_out_exit;
	}

	h = strdup(hash);
	if (!h) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	hash = h;

	while (hash) {
		p = strchr(hash, ' ');
		if (p)
			*p++ = '\0';

		err = snprintf(trans, sizeof(trans), "dc%d_", region);
		if (!strncmp(trans, hash, err)) {
			err = dnet_move_transform(n, hash, tail);
		}

		hash = p;
		while (hash && *hash && isspace(*hash))
			hash++;
	}
	free(h);

	return 0;

err_out_exit:
	return err;
}

static int dnet_fcgi_external_start(struct dnet_node *n, char *query, char *addr, char *id, int length)
{
	return dnet_fcgi_external_raw(n, query, addr, id, length, 0);
}

static int dnet_fcgi_external_stop(struct dnet_node *n, char *query, char *addr, char *id, int length)
{
	int err;

	if (!id || !length)
		return 0;

	err = dnet_fcgi_external_raw(n, query, addr, id, length, 1);
	if (err)
		return err;

	return dnet_fcgi_external_callback_start(query, addr, id, length);
}

static void dnet_fcgi_output_content_type(char *id)
{
	int i;
	struct dnet_fcgi_content_type *c;

	for (i=0; i<dnet_fcgi_ctypes_num; ++i) {
		c = &dnet_fcgi_ctypes[i];

		if (strcasestr(id, c->ext)) {
			dnet_fcgi_output("Content-type: %s\r\n", c->type);
			return;
		}
	}
	
	dnet_fcgi_output("Content-type: octet/stream\r\n");
}

static int dnet_fcgi_handle_get(struct dnet_node *n, char *query, char *addr, char *id, int length, int version)
{
	int err;
	char *p;
	struct dnet_io_control ctl, *c = NULL;

	if (dnet_fcgi_unlink_pattern && strstr(query, dnet_fcgi_unlink_pattern))
		return dnet_fcgi_unlink(n, id, length, version);

	if (dnet_fcgi_direct_download) {
		int i;

		p = strstr(query, dnet_fcgi_direct_download);
		if (!p)
			goto lookup;

		for (i=0; i<dnet_fcgi_direct_patterns_num; ++i) {
			p = strstr(query, dnet_fcgi_direct_patterns[i]);
			if (p)
				break;
		}

		if (i != dnet_fcgi_direct_patterns_num) {
			memset(&ctl, 0, sizeof(struct dnet_io_control));

			dnet_fcgi_output_content_type(id);

			ctl.fd = -1;
			ctl.complete = dnet_fcgi_read_complete;
			ctl.cmd = DNET_CMD_READ;
			ctl.cflags = DNET_FLAGS_NEED_ACK;

			c = &ctl;
		} else {
			/*
			 * Do not try non-direct download if
			 * unsupported type was requested.
			 */

			err = -EINVAL;
			goto out_exit;
		}
	}

lookup:
	err = dnet_fcgi_process_io(n, id, length, c, version);
	if (err) {
		fprintf(dnet_fcgi_log, "%s: Failed to lookup object '%s': %d.\n", addr, id, err);
		goto out_exit;
	}

out_exit:
	return err;
}

static int dnet_fcgi_setup_content_type_patterns(char *__patterns)
{
	char *patterns = strdup(__patterns);
	char *tmp, *token, *saveptr;
	struct dnet_fcgi_content_type cn;
	int i, err = -ENOMEM;

	if (!patterns)
		goto err_out_exit;

	tmp = patterns;
	while (1) {
		token = strtok_r(tmp, DNET_FCGI_TOKEN_STRING, &saveptr);
		if (!token)
			break;

		tmp = strchr(token, DNET_FCGI_TOKEN_DELIM);
		if (!tmp) {
			err = -EINVAL;
			goto err_out_free_ctypes;
		}

		*tmp++ = '\0';

		snprintf(cn.ext, sizeof(cn.ext), "%s", token);
		snprintf(cn.type, sizeof(cn.type), "%s", tmp);

		dnet_fcgi_ctypes_num++;
		dnet_fcgi_ctypes = realloc(dnet_fcgi_ctypes,
				dnet_fcgi_ctypes_num * sizeof(struct dnet_fcgi_content_type));
		if (!dnet_fcgi_ctypes) {
			err = -ENOMEM;
			goto err_out_free_ctypes;
		}

		memcpy(&dnet_fcgi_ctypes[dnet_fcgi_ctypes_num - 1], &cn, sizeof(struct dnet_fcgi_content_type));

		tmp = NULL;
	}

	for (i=0; i<dnet_fcgi_ctypes_num; ++i) {
		struct dnet_fcgi_content_type *c = &dnet_fcgi_ctypes[i];

		fprintf(dnet_fcgi_log, "%s -> %s\n", c->ext, c->type);
	}

	free(patterns);

	return 0;

err_out_free_ctypes:
	free(dnet_fcgi_ctypes);
	dnet_fcgi_ctypes = NULL;
	dnet_fcgi_ctypes_num = 0;
	free(patterns);
err_out_exit:
	return err;
}

static int dnet_fcgi_setup_external_callbacks(char *name)
{
	int err = -EINVAL;
	void *lib;
	int (* init)(char *data);
	char *data;

	lib = dlopen(name, RTLD_NOW);
	if (!lib) {
		fprintf(dnet_fcgi_log, "Failed to load external library '%s': %s.\n",
				name, dlerror());
		goto err_out_exit;
	}

	dnet_fcgi_external_callback_start = dlsym(lib, DNET_FCGI_EXTERNAL_CALLBACK_START);
	if (!dnet_fcgi_external_callback_start) {
		fprintf(dnet_fcgi_log, "Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_CALLBACK_START, name);
		goto err_out_close;
	}

	dnet_fcgi_external_callback_stop = dlsym(lib, DNET_FCGI_EXTERNAL_CALLBACK_STOP);
	if (!dnet_fcgi_external_callback_stop) {
		fprintf(dnet_fcgi_log, "Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_CALLBACK_STOP, name);
		goto err_out_null;
	}

	init = dlsym(lib, DNET_FCGI_EXTERNAL_INIT);
	if (!init) {
		fprintf(dnet_fcgi_log, "Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_INIT, name);
		goto err_out_null;
	}

	dnet_fcgi_external_exit = dlsym(lib, DNET_FCGI_EXTERNAL_EXIT);
	if (!dnet_fcgi_external_exit) {
		fprintf(dnet_fcgi_log, "Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_EXIT, name);
		goto err_out_null;
	}

	data = getenv("DNET_FCGI_EXTERNAL_DATA");
	err = init(data);
	if (err) {
		fprintf(dnet_fcgi_log, "Failed to initialize external library '%s' using data '%s'.\n",
				name, data);
		goto err_out_null;
	}

	fprintf(dnet_fcgi_log, "Successfully initialized external library '%s' using data '%s'.\n",
				name, data);

	return 0;

err_out_null:
	dnet_fcgi_external_exit = NULL;
	dnet_fcgi_external_callback_start = NULL;
	dnet_fcgi_external_callback_stop = NULL;
err_out_close:
	dlclose(lib);
err_out_exit:
	return err;
}

static int dnet_fcgi_output_permanent_headers(void)
{
	int i;

	for (i=0; i<dnet_fcgi_pheaders_num; ++i) {
		fprintf(dnet_fcgi_log, "%s\r\n", dnet_fcgi_pheaders[i]);
		dnet_fcgi_output("%s\r\n", dnet_fcgi_pheaders[i]);
	}

	return 0;
}

static int dnet_fcgi_setup_permanent_headers(void)
{
	char *env = getenv("DNET_FCGI_PERMANENT_HEADERS");
	int err = -ENOENT, i;
	char *tmp, *saveptr, *token;
	
	if (!env)
		goto err_out_exit;

	tmp = strdup(env);
	if (!tmp) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	env = tmp;

	while (1) {
		token = strtok_r(tmp, DNET_FCGI_TOKEN_HEADER_SPLIT_STRING, &saveptr);
		if (!token)
			break;

		dnet_fcgi_pheaders_num++;
		dnet_fcgi_pheaders = realloc(dnet_fcgi_pheaders, dnet_fcgi_pheaders_num * sizeof(char *));
		if (!dnet_fcgi_pheaders) {
			err = -ENOMEM;
			goto err_out_free_all;
		}

		fprintf(dnet_fcgi_log, "Added '%s' permanent header.\n", token);

		dnet_fcgi_pheaders[dnet_fcgi_pheaders_num - 1] = strdup(token);
		if (!dnet_fcgi_pheaders[dnet_fcgi_pheaders_num - 1]) {
			err = -ENOMEM;
			dnet_fcgi_pheaders_num--;
			goto err_out_free_all;
		}

		tmp = NULL;
	}

	free(env);
	return 0;

err_out_free_all:
	for (i=0; i<dnet_fcgi_pheaders_num; ++i)
		free(dnet_fcgi_pheaders[i]);
	free(dnet_fcgi_pheaders);
	dnet_fcgi_pheaders_num = 0;
	free(env);
err_out_exit:
	return err;
}

static void dnet_fcgi_destroy_permanent_headers()
{
	int i;

	for (i=0; i<dnet_fcgi_pheaders_num; ++i)
		free(dnet_fcgi_pheaders[i]);

	free(dnet_fcgi_pheaders);
	dnet_fcgi_pheaders_num = 0;
}

int main()
{
	char *p, *addr, *reason, *method, *query;
	char *id_pattern, *id_delimiter, *direct_patterns = NULL, *version_pattern, *version_str;
	int length, id_pattern_length, err, post_allowed, version_pattern_len;
	int version;
	char *id, *end;
	struct dnet_config cfg;
	struct dnet_node *n;
	char tmp[128];

	dnet_fcgi_status_pattern = getenv("DNET_FCGI_SUCCESS_STATUS_PATTERN");
	if (!dnet_fcgi_status_pattern)
		dnet_fcgi_status_pattern = DNET_FCGI_SUCCESS_STATUS_PATTERN;

	dnet_fcgi_root_pattern = getenv("DNET_FCGI_ROOT_PATTERN");
	if (!dnet_fcgi_root_pattern)
		dnet_fcgi_root_pattern = DNET_FCGI_ROOT_PATTERN;

	p = getenv("DNET_FCGI_MAX_REQUEST_SIZE");
	if (p)
		dnet_fcgi_max_request_size = strtoul(p, NULL, 0);

	if (!dnet_fcgi_max_request_size)
		dnet_fcgi_max_request_size = DNET_FCGI_MAX_REQUEST_SIZE;

	p = getenv("DNET_FCGI_LOG");
	if (!p)
		p = DNET_FCGI_LOG;

	snprintf(tmp, sizeof(tmp), "%s.%d", p, getpid());
	p = tmp;

	dnet_fcgi_log = fopen(p, "a");
	if (!dnet_fcgi_log) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s' log file.\n", p);
		goto err_out_exit;
	}

	p = getenv("DNET_FCGI_BASE_PORT");
	if (!p) {
		err = -ENOENT;
		fprintf(dnet_fcgi_log, "No DNET_FCGI_BASE_PORT provided, I will not be able to determine proper directory to fetch objects.\n");
		goto err_out_close;
	}
	dnet_fcgi_base_port = atoi(p);

	dnet_fcgi_unlink_pattern = getenv("DNET_FCGI_UNLINK_PATTERN_URI");
	dnet_fcgi_stat_pattern = getenv("DNET_FCGI_STAT_PATTERN_URI");
	p = getenv("DNET_FCGI_STAT_BAD_LIMIT");
	if (p)
		dnet_fcgi_stat_bad_limit = atoi(p);
	dnet_fcgi_stat_log_pattern = getenv("DNET_FCGI_STAT_LOG_PATTERN_URI");

	fprintf(dnet_fcgi_log, "stat pattern: %s\n", dnet_fcgi_stat_pattern);

	dnet_fcgi_direct_download = getenv("DNET_FCGI_DIRECT_PATTERN_URI");
	if (dnet_fcgi_direct_download) {
		p = getenv("DNET_FCGI_DIRECT_PATTERNS");
		if (!p) {
			dnet_fcgi_direct_download = NULL;
		} else {
			char *tmp = strdup(p);
			char *saveptr, *token;

			if (!tmp) {
				err = -ENOMEM;
				goto err_out_close;
			}

			direct_patterns = tmp;

			while (1) {
				token = strtok_r(tmp, DNET_FCGI_TOKEN_STRING, &saveptr);
				if (!token)
					break;

				dnet_fcgi_direct_patterns_num++;
				dnet_fcgi_direct_patterns = realloc(dnet_fcgi_direct_patterns,
						dnet_fcgi_direct_patterns_num * sizeof(char *));
				if (!dnet_fcgi_direct_patterns) {
					err = -ENOMEM;
					goto err_out_free_direct_patterns;
				}

				fprintf(dnet_fcgi_log, "Added '%s' direct download pattern.\n", token);

				dnet_fcgi_direct_patterns[dnet_fcgi_direct_patterns_num - 1] = token;
				tmp = NULL;
			}
		}
	}


	err = dnet_fcgi_fill_config(&cfg);
	if (err) {
		fprintf(dnet_fcgi_log, "Failed to parse config.\n");
		goto err_out_free_direct_patterns;
	}

	err = dnet_fcgi_setup_sign_hash();
	if (err)
		goto err_out_close;

	n = dnet_node_create(&cfg);
	if (!n)
		goto err_out_sign_destroy;

	err = dnet_fcgi_add_remote_addr(n, &cfg);
	if (err)
		goto err_out_free;

	err = dnet_fcgi_add_transform(n);
	if (err)
		goto err_out_free;

	dnet_fcgi_setup_permanent_headers();

	p = getenv("DNET_FCGI_DNS_LOOKUP");
	if (p)
		dnet_fcgi_dns_lookup = atoi(p);

	p = getenv("DNET_FCGI_UPLOAD_HOST_LIMIT");
	if (p)
		dnet_fcgi_upload_host_limit = atoi(p);

	p = getenv("DNET_FCGI_RANDOM_HASHES");
	if (p) {
		dnet_fcgi_random_hashes = atoi(p);
		srand(time(NULL));
	}

	p = getenv("DNET_FCGI_TOLERATE_UPLOAD_ERROR_COUNT");
	if (p)
		dnet_fcgi_tolerate_upload_error_count = atoi(p);

	p = getenv("DNET_FCGI_CONTENT_TYPES");
	if (p)
		dnet_fcgi_setup_content_type_patterns(p);

	p = getenv("DNET_FCGI_EXTERNAL_LIB");
	if (p)
		dnet_fcgi_setup_external_callbacks(p);

	post_allowed = 0;
	p = getenv("DNET_FCGI_POST_ALLOWED");
	if (p)
		post_allowed = atoi(p);

	p = getenv("DNET_FCGI_LAST_MODIFIED");
	if (p)
		dnet_fcgi_last_modified = atoi(p);

	p = getenv("DNET_FCGI_STORAGE_BITS");
	if (p)
		dnet_fcgi_bit_num = ALIGN(atoi(p), 4);

	fprintf(dnet_fcgi_log, "Started on %s, POST is %s.\n", getenv("SERVER_ADDR"), (post_allowed) ? "allowed" : "not allowed");
	fflush(dnet_fcgi_log);

	id_pattern = getenv("DNET_FCGI_ID_PATTERN");
	id_delimiter = getenv("DNET_FCGI_ID_DELIMITER");
	version_pattern = getenv("DNET_FCGI_VERSION_PATTERN");

	if (!id_pattern)
		id_pattern = DNET_FCGI_ID_PATTERN;
	if (!id_delimiter)
		id_delimiter = DNET_FCGI_ID_DELIMITER;
	if (!version_pattern)
		version_pattern = DNET_FCGI_VERSION_PATTERN;
	version_pattern_len = strlen(version_pattern);

	id_pattern_length = strlen(id_pattern);

	err = FCGX_Init();
	if (err) {
		fprintf(dnet_fcgi_log, "FCGX initaliation failed: %d.\n", err);
		goto err_out_free;
	}

	err = FCGX_InitRequest(&dnet_fcgi_request, LISTENSOCK_FILENO, LISTENSOCK_FLAGS);
	if (err) {
		fprintf(dnet_fcgi_log, "FCGX request initaliation failed: %d.\n", err);
		goto err_out_fcgi_exit;
	}

	while (1) {
		err = FCGX_Accept_r(&dnet_fcgi_request);
		if (err || !dnet_fcgi_request.in || !dnet_fcgi_request.out || !dnet_fcgi_request.err || !dnet_fcgi_request.envp) {
			fprintf(dnet_fcgi_log, "Failed to accept client: no IO streams: in: %p, out: %p, err: %p, env: %p, err: %d.\n",
					dnet_fcgi_request.in, dnet_fcgi_request.out, dnet_fcgi_request.err, dnet_fcgi_request.envp, err);
			continue;
		}

		pthread_mutex_lock(&dnet_fcgi_output_lock);
		dnet_fcgi_request_info = 1;
		pthread_mutex_unlock(&dnet_fcgi_output_lock);

		addr = FCGX_GetParam("REMOTE_ADDR", dnet_fcgi_request.envp);
		if (!addr)
			continue;

		method = FCGX_GetParam("REQUEST_METHOD", dnet_fcgi_request.envp);
		id = NULL;
		length = 0;

		err = -EINVAL;
		query = p = FCGX_GetParam("QUERY_STRING", dnet_fcgi_request.envp);
		if (!p) {
			reason = "no query string";
			goto err_continue;
		}

		fprintf(dnet_fcgi_log, "query: '%s'.\n", query);

		if (dnet_fcgi_stat_log_pattern) {
			if (!strcmp(query, dnet_fcgi_stat_log_pattern)) {
				dnet_fcgi_stat_log(n);
				goto cont;
			}
		}

		if (dnet_fcgi_stat_pattern) {
			if (!strcmp(query, dnet_fcgi_stat_pattern)) {
				dnet_fcgi_stat(n);
				goto cont;
			}
		}

		p = query;
		id = strstr(p, id_pattern);
		if (!id) {
			reason = "malformed request, no id part";
			goto err_continue;
		}

		id += id_pattern_length;
		if (!*id) {
			reason = "malformed request, no id part";
			goto err_continue;
		}

		end = strstr(id, id_delimiter);
		if (!end)
			end = id + strlen(id);

		length = end - id;

		version = -1;
		version_str = strstr(query, version_pattern);
		if (version_str) {
			version_str += version_pattern_len;
			if (*version_str)
				version = strtol(version_str, NULL, 0);
		}

		fprintf(dnet_fcgi_log, "id: '%s', length: %d, version: %d.\n", id, length, version);

		if (dnet_fcgi_external_callback_start)
			dnet_fcgi_external_start(n, query, addr, id, length);

		dnet_fcgi_output_permanent_headers();

		if (!strncmp(method, "POST", 4)) {
			if (!post_allowed) {
				err = -EACCES;
				fprintf(dnet_fcgi_log, "%s: POST is not allowed for object '%s'.\n", addr, id);
				reason = "POST is not allowed";
				goto err_continue;
			}

			err = dnet_fcgi_handle_post(n, addr, id, length, version);
			if (err) {
				fprintf(dnet_fcgi_log, "%s: Failed to handle POST for object '%s': %d.\n", addr, id, err);
				reason = "failed to handle POST";
				goto err_continue;
			}
		} else {
			err = dnet_fcgi_handle_get(n, query, addr, id, length, version);
			if (err) {
				fprintf(dnet_fcgi_log, "%s: Failed to handle GET for object '%s': %d.\n", addr, id, err);
				reason = "failed to handle GET";
				goto err_continue;
			}
		}

cont:
		if (dnet_fcgi_external_callback_stop)
			dnet_fcgi_external_stop(n, query, addr, id, length);

		pthread_mutex_lock(&dnet_fcgi_output_lock);
		FCGX_Finish_r(&dnet_fcgi_request);
		dnet_fcgi_request_info = 0;
		pthread_mutex_unlock(&dnet_fcgi_output_lock);
		continue;

err_continue:
		dnet_fcgi_output("Cache-control: no-cache\r\n");
		dnet_fcgi_output("Content-Type: text/plain\r\n");
		dnet_fcgi_output("Status: %d\r\n\r\n", (err == -ENOENT) ? 404 : 403);
		dnet_fcgi_output("Reason: %s: %s [%d]\r\n", reason, strerror(-err), err);
		if (query)
			dnet_fcgi_output("Query: %s\r\n", query);
		fprintf(dnet_fcgi_log, "%s: bad request: %s: %s [%d]\n", addr, reason, strerror(-err), err);
		fflush(dnet_fcgi_log);
		goto cont;
	}

	dnet_node_destroy(n);
	dnet_fcgi_destroy_sign_hash();

	free(direct_patterns);
	free(dnet_fcgi_direct_patterns);
	dnet_fcgi_destroy_permanent_headers();

	if (dnet_fcgi_external_exit)
		dnet_fcgi_external_exit();

	fflush(dnet_fcgi_log);
	fclose(dnet_fcgi_log);

	return 0;

err_out_fcgi_exit:
	FCGX_ShutdownPending();
err_out_free:
	dnet_node_destroy(n);
err_out_sign_destroy:
	dnet_fcgi_destroy_sign_hash();
err_out_free_direct_patterns:
	free(direct_patterns);
	free(dnet_fcgi_direct_patterns);
err_out_close:
	fflush(dnet_fcgi_log);
	fclose(dnet_fcgi_log);
err_out_exit:
	return err;
}
