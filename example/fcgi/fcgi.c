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
#include <syslog.h>
#include <unistd.h>

#include <fcgiapp.h>

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#include "hash.h"
#include "common.h"
#include "backends.h"

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define DNET_FCGI_ID_PATTERN		"id="
#define DNET_FCGI_ID_DELIMITER		"&"
#define DNET_FCGI_VERSION_PATTERN	"version="
#define DNET_FCGI_TIMESTAMP_PATTERN	"timestamp="
#define DNET_FCGI_APPEND_PATTERN	"append"
#define DNET_FCGI_EMBED_PATTERN		"embed"
#define DNET_FCGI_MULTIPLE_PATTERN	"multiple="
#define DNET_FCGI_LOG			"/tmp/dnet_fcgi.log"
#define DNET_FCGI_TMP_DIR		"/tmp"
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
#define DNET_FCGI_TOKEN_DIRECT_ALL	'*'
#define DNET_FCGI_STORAGE_BIT_NUM	8
#define DNET_FCGI_ADDR_HEADER		"REMOTE_ADDR"
#define DNET_FCGI_GROUPS_PATTERN	"groups="

static long dnet_fcgi_timeout_sec = 10;

static struct dnet_log fcgi_logger;

static FILE *dnet_fcgi_log = NULL;
static pthread_cond_t dnet_fcgi_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dnet_fcgi_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int dnet_fcgi_request_completed, dnet_fcgi_request_init_value = 11223344, dnet_fcgi_request_error;
static char *dnet_fcgi_status_pattern, *dnet_fcgi_root_pattern;
static int dnet_fcgi_tolerate_upload_error_count;
static int dnet_fcgi_group_num;
static unsigned long dnet_fcgi_max_request_size;
static int dnet_fcgi_base_port;
static uint64_t dnet_fcgi_bit_num = DNET_FCGI_STORAGE_BIT_NUM;
static unsigned char dnet_fcgi_id[DNET_ID_SIZE];
static uint64_t dnet_fcgi_trans_tsec;
static int dnet_fcgi_post_allowed;

static char *dnet_fcgi_post_buf;
static int dnet_fcgi_post_len, dnet_fcgi_post_buf_size;

static int *dnet_fcgi_groups;
static int dnet_fcgi_group_num;
static char *dnet_fcgi_groups_pattern = DNET_FCGI_GROUPS_PATTERN;
static int dnet_fcgi_groups_pattern_len;

static int dnet_fcgi_last_modified;

static char *dnet_fcgi_direct_download;
static int dnet_fcgi_direct_patterns_num, dnet_fcgi_direct_download_all;
static char **dnet_fcgi_direct_patterns;

static char *dnet_fcgi_remote_addr_header = DNET_FCGI_ADDR_HEADER;

static int dnet_fcgi_upload_host_limit;

static struct timeval dnet_fcgi_read_time;

static char *dnet_fcgi_tmp_dir;
int dnet_fcgi_tmp_dir_len;

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

static int dnet_fcgi_use_la_check;

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
static int dnet_fcgi_region = -1, dnet_fcgi_put_region;

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

enum {
	DNET_FCGI_EMBED_DATA		= 1,
	DNET_FCGI_EMBED_TIMESTAMP,
} dnet_fcgi_embed_types;

struct dnet_fcgi_embed {
	uint64_t		size;
	uint32_t		type;
	uint32_t		flags;
	uint8_t			data[0];
};

static inline void dnet_fcgi_convert_embedded(struct dnet_fcgi_embed *e)
{
	e->size = dnet_bswap64(e->size);
	e->type = dnet_bswap32(e->type);
	e->flags = dnet_bswap32(e->flags);
}

#define dnet_fcgi_log_write(fmt, a...) do { if (dnet_fcgi_log) fprintf(dnet_fcgi_log, fmt, ##a); else syslog(LOG_INFO, fmt, ##a); } while (0)

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
	int i = 0, num = 5;
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
			dnet_fcgi_log_write("%d/%d: failed to output %d bytes: %s [%d].\n",
					i, num, size, strerror(errno), errno);

			if (++i >= num)
				break;

			usleep(50000);
			continue;
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

	cfg->log = &fcgi_logger;

	cfg->log->log_mask = DNET_LOG_ERROR | DNET_LOG_INFO;
	if (dnet_fcgi_log) {
		cfg->log->log = dnet_common_log;
		cfg->log->log_private = dnet_fcgi_log;
	} else {
		cfg->log->log = dnet_syslog;
		cfg->log->log_private = NULL;
	}

	p = getenv("DNET_FCGI_NODE_LOG_MASK");
	if (p)
		cfg->log->log_mask = strtoul(p, NULL, 0);

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

static int dnet_fcgi_output_permanent_headers(void)
{
	int i;

	for (i=0; i<dnet_fcgi_pheaders_num; ++i) {
		dnet_fcgi_output("%s\r\n", dnet_fcgi_pheaders[i]);
	}

	return 0;
}

static void dnet_fcgi_data_to_hex(char *dst, unsigned int dlen, unsigned char *src, unsigned int slen)
{
	unsigned int i;

	if (slen > dlen/2 - 1)
		slen = dlen/2 - 1;

	for (i=0; i<slen; ++i)
		sprintf(&dst[2*i], "%02x", src[i]);
}

static int dnet_fcgi_generate_sign(struct dnet_node *n, long timestamp)
{
	char *cookie = FCGX_GetParam(dnet_fcgi_cookie_header, dnet_fcgi_request.envp);
	struct dnet_crypto_engine *e = dnet_fcgi_sign_hash;
	int err, len;
	char cookie_res[256];
	unsigned int rsize = sizeof(dnet_fcgi_sign_data);

	if (cookie) {
		char *val, *end;

		dnet_log_raw(n, DNET_LOG_NOTICE, "Found cookie: '%s'.\n", cookie);

		val = strstr(cookie, dnet_fcgi_cookie_delimiter);

		if (!val || ((signed)strlen(cookie) <= dnet_fcgi_cookie_delimiter_len)) {
			dnet_log_raw(n, DNET_LOG_ERROR, "wrong cookie '%s', generating new one.\n", cookie);
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
			dnet_log_raw(n, DNET_LOG_ERROR, "Failed to read random data: %s [%d].\n",
					strerror(errno), errno);
			goto err_out_exit;
		}

		cookie = dnet_fcgi_sign_tmp;
		len = snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%s%x%lx", dnet_fcgi_cookie_key, tmp, timestamp);

		e->transform(e, dnet_fcgi_sign_tmp, len, dnet_fcgi_sign_data, &rsize, 0);

		dnet_fcgi_data_to_hex(cookie_res, sizeof(cookie_res), (unsigned char *)dnet_fcgi_sign_data, rsize);
		snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%x.%lx.%s", tmp, timestamp, cookie_res);

		dnet_log_raw(n, DNET_LOG_INFO, "Cookie generation: '%s' [%d bytes] -> '%s' : '%s%s'\n",
				dnet_fcgi_sign_tmp, len, cookie_res,
				dnet_fcgi_cookie_delimiter, dnet_fcgi_sign_tmp);

		dnet_fcgi_output("Set-Cookie: %s%s", dnet_fcgi_cookie_delimiter, dnet_fcgi_sign_tmp);
		if (dnet_fcgi_expiration_interval) {
			char str[128];
			struct tm tm;
			time_t t = timestamp + dnet_fcgi_expiration_interval;

			localtime_r(&t, &tm);
			strftime(str, sizeof(str), "%a, %d-%b-%Y %T %Z", &tm);
			dnet_fcgi_output("%s expires=%s%s", dnet_fcgi_cookie_ending, str, dnet_fcgi_cookie_addon);
		}
		dnet_fcgi_output("\r\n");

		snprintf(cookie_res, sizeof(cookie_res), "%s", dnet_fcgi_sign_tmp);
	}

	err = 0;
	len = snprintf(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), "%s%lx%s", dnet_fcgi_sign_key, timestamp, cookie_res);

	rsize = sizeof(dnet_fcgi_sign_data);
	e->transform(e, dnet_fcgi_sign_tmp, len, dnet_fcgi_sign_data, &rsize, 0);

	dnet_fcgi_data_to_hex(dnet_fcgi_sign_tmp, sizeof(dnet_fcgi_sign_tmp), (unsigned char *)dnet_fcgi_sign_data, rsize);

	dnet_log_raw(n, DNET_LOG_INFO, "Sign generation: '%s %lx %s' [%d bytes] -> '%s'\n",
			dnet_fcgi_sign_key, timestamp, cookie_res, len, dnet_fcgi_sign_tmp);

err_out_exit:
	return err;
}

static int dnet_fcgi_put_last_modified(void)
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
	struct dnet_node *n;
	struct dnet_addr_attr *a;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	n = dnet_get_node_from_state(st);

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		err = dnet_lookup_complete(st, cmd, attr, priv);
		if (err && err != -EEXIST)
			goto err_out_exit;

		a = (struct dnet_addr_attr *)(attr + 1);
#if 1
		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: addr: %s, is object presented there: %d.\n",
				dnet_dump_id(&cmd->id),
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

			dnet_dump_id_len_raw(dnet_fcgi_id, DNET_ID_SIZE, id);
			file_backend_get_dir(dnet_fcgi_id, dnet_fcgi_bit_num, hex_dir);

			if (dnet_fcgi_dns_lookup) {
				err = getnameinfo((struct sockaddr *)a->addr.addr, a->addr.addr_len,
						addr, sizeof(addr), NULL, 0, 0);
				if (err)
					snprintf(addr, sizeof(addr), "%s", dnet_state_dump_addr_only(&a->addr));
			} else {
				snprintf(addr, sizeof(addr), "%s", dnet_state_dump_addr_only(&a->addr));
			}

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
				err = dnet_fcgi_generate_sign(n, timestamp);
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

			if (dnet_fcgi_put_region)
				dnet_fcgi_output("<region>%d</region>", dnet_fcgi_region);

			if (dnet_fcgi_sign_key)
				dnet_fcgi_output("<s>%s</s>", dnet_fcgi_sign_tmp);
			dnet_fcgi_output("</download-info>\r\n");

			dnet_fcgi_log_write("%d: <?xml version=\"1.0\" encoding=\"utf-8\"?>"
					"<download-info><host>%s</host><path>%s/%d/%s/%s</path><ts>%lx</ts>"
					"<region>%d</region>",
					getpid(),
					addr,
					dnet_fcgi_root_pattern, port - dnet_fcgi_base_port,
					hex_dir,
					id,
					timestamp,
					dnet_fcgi_region);

			if (dnet_fcgi_sign_key)
				dnet_fcgi_log_write("<s>%s</s>", dnet_fcgi_sign_tmp);
			dnet_fcgi_log_write("</download-info>\n");


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

static int dnet_fcgi_get_data_version_id(struct dnet_node *n, struct dnet_id *id, unsigned char *dst,
		uint64_t *tsec, int version, int unlink_upload)
{
	char file[32 + dnet_fcgi_tmp_dir_len + 1 + 2*DNET_ID_SIZE + sizeof(DNET_HISTORY_SUFFIX)]; /* 32 is for pid length */
	char id_str[2*DNET_ID_SIZE+1];
	struct dnet_history_map m;
	struct dnet_history_entry *e;
	int err, stored_version;
	long i;

	snprintf(file, sizeof(file), "%s/%s-%d", dnet_fcgi_tmp_dir, dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, id_str), getpid());

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

		stored_version = dnet_common_get_version(e->id);

		dnet_log_raw(n, DNET_LOG_DSA, "%s: stored: %d, version: %d, deleted: %d.\n",
				dnet_dump_id_str(e->id), stored_version, version, !!e->flags);

		if (stored_version <= version) {
			dnet_convert_history_entry(e);
			/* If requested version was removed we have to return error */
			if (e->flags & DNET_IO_FLAGS_REMOVED)
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
			e->flags |= DNET_IO_FLAGS_REMOVED;
			dnet_convert_history_entry(e);

			err = dnet_write_file_local_offset(n, file, file, strlen(file), id, 0, 0, 0,
					DNET_ATTR_DIRECT_TRANSACTION, DNET_IO_FLAGS_HISTORY);
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

	err = dnet_fcgi_get_data_version_id(n, &ctl->id, NULL, NULL, version, 1);
	if (err)
		return err;

	return dnet_trans_alloc_send(n, ctl);
}

static int dnet_fcgi_unlink(struct dnet_node *n, struct dnet_id *id, int version)
{
	int num = 0, i;
	int err, error = -ENOENT;
	struct dnet_trans_control ctl;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.complete = dnet_fcgi_unlink_complete;
	ctl.cmd = DNET_CMD_DEL;
	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.aflags = DNET_ATTR_DIRECT_TRANSACTION;

	dnet_fcgi_request_completed = 0;
	for (i=0; i<dnet_fcgi_group_num; ++i) {
		dnet_setup_id(&ctl.id, dnet_fcgi_groups[i], id->id);

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
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to wait for removal completion: %d.\n", dnet_dump_id(id), err);
		error = err;
	}
	return error;
}

static int dnet_fcgi_get_data(struct dnet_node *n, struct dnet_id *id, struct dnet_io_control *ctl, uint64_t *tsec, int embed)
{
	int err;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	if (dnet_fcgi_last_modified && !embed && !dnet_fcgi_trans_tsec) {
		uint64_t tsec_local;

		err = 0;
		if (!tsec) {
			tsec = &tsec_local;
			err = dnet_fcgi_get_data_version_id(n, id, NULL, tsec, INT_MAX, 0);
			if (err)
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to get last timestamp: %d.\n",
						dnet_dump_id(id), err);
		}

		dnet_fcgi_trans_tsec = *tsec;
	}

	dnet_fcgi_request_completed = dnet_fcgi_request_init_value;

	if (ctl) {
		memcpy(ctl->io.id, ctl->id.id, DNET_ID_SIZE);
		memcpy(ctl->io.parent, ctl->id.id, DNET_ID_SIZE);
		memcpy(&ctl->id, id, sizeof(struct dnet_id));

		err = dnet_read_object(n, ctl);
	} else {
		err = dnet_lookup_object(n, id, DNET_ATTR_LOOKUP_STAT,
				dnet_fcgi_lookup_complete, NULL);
	}

	if (err)
		goto err_out_exit;

	err = dnet_fcgi_wait(dnet_fcgi_request_completed != dnet_fcgi_request_init_value, &ts);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: IO wait completion failed: %d.\n", dnet_dump_id(id), err);
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

static int dnet_fcgi_get_data_version(struct dnet_node *n, struct dnet_id *id, struct dnet_io_control *ctl, int version)
{
	int err;
	unsigned char dst[DNET_ID_SIZE];
	uint64_t tsec;

	err = dnet_fcgi_get_data_version_id(n, id, dst, &tsec, version, 0);
	if (err)
		return err;

	dnet_setup_id(id, id->group_id, dst);
	return dnet_fcgi_get_data(n, id, ctl, &tsec, 0);
}

static int dnet_fcgi_process_io(struct dnet_node *n, struct dnet_id *id, struct dnet_io_control *ctl,
		int version, int embed, int multiple)
{
	int err, error = -ENOENT;
	int random_num = 0, i;
	int *groups = NULL;
	struct dnet_id_param *ids = NULL;
	int ids_num = 0;

	if (multiple) {
		err = dnet_read_multiple(n, id, multiple, &ids);
		if (err <= 0)
			return err;
		ids_num = err;
	} else if (dnet_fcgi_use_la_check) {
		err = dnet_generate_ids_by_param(n, id, DNET_ID_PARAM_LA, &ids);
		if (err <= 0)
			return err;
		ids_num = err;
	} else {
		int i;

		groups = alloca(sizeof(int) * dnet_fcgi_group_num);
		for (i=0; i<dnet_fcgi_group_num; ++i)
			groups[i] = dnet_fcgi_groups[i];
		ids_num = dnet_fcgi_group_num;
	}

	for (i=0; i<ids_num; ++i) {
		if (dnet_fcgi_use_la_check || multiple) {
			id->group_id = ids[i].group_id;
		} else {
			if (random_num < ids_num) {
				int r;

				r = (double)(ids_num - random_num) * rand() / ((double)RAND_MAX);

				id->group_id = groups[r];
				dnet_log_raw(n, DNET_LOG_DSA, "Using r: %d, group: %d, total groups: %d.\n", r, id->group_id, ids_num);

				for (; r<ids_num-1; r++)
					groups[r] = groups[r+1];

				random_num++;
			}
		}

		dnet_fcgi_trans_tsec = 0;
		if (multiple)
			dnet_fcgi_trans_tsec = ids[i].param;

		if (version == -1) {
			err = dnet_fcgi_get_data(n, id, ctl, NULL, embed);
		} else {
			err = dnet_fcgi_get_data_version(n, id, ctl, version);
		}
		dnet_log_raw(n, DNET_LOG_NOTICE, "%s: %d\n", dnet_dump_id_len(id, DNET_ID_SIZE), err);

		if (err) {
			error = err;
			continue;
		}

		error = 0;
		break;
	}

	free(ids);

	return error;
}

static int dnet_fcgi_upload_complete(struct dnet_net_state *st, struct dnet_cmd *cmd,
		struct dnet_attr *attr __unused, void *priv __unused)
{
	int err = 0, port;
	struct dnet_addr *addr;
	char id_str[DNET_ID_SIZE*2+1];
	char hex_dir[2*DNET_ID_SIZE+1];

	if (!cmd || !st) {
		err = -EINVAL;
		goto out_wakeup;
	}

	if (cmd->status)
		err = cmd->status;

	if (cmd->flags & DNET_FLAGS_MORE)
		return err;

out_wakeup:
	if (st && err) {
		dnet_log_raw(dnet_get_node_from_state(st), DNET_LOG_ERROR, "%s: upload completed: %d, err: %d.\n",
			dnet_dump_id(&cmd->id), dnet_fcgi_request_completed, err);
	}

	file_backend_get_dir(cmd->id.id, dnet_fcgi_bit_num, hex_dir);
	dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id_str);

	addr = dnet_state_addr(st);
	port = dnet_server_convert_port((struct sockaddr *)addr->addr, addr->addr_len);

	dnet_fcgi_post_len += snprintf(dnet_fcgi_post_buf + dnet_fcgi_post_len, dnet_fcgi_post_buf_size - dnet_fcgi_post_len,
			"<complete addr=\"%s\" path=\"%s/%d/%s/%s\" group=\"%d\" status=\"%d\"/>",
			dnet_state_dump_addr(st),
			dnet_fcgi_root_pattern,
			port - dnet_fcgi_base_port,
			hex_dir, id_str,
			cmd->id.group_id, err);
	dnet_fcgi_wakeup({
				do {
					dnet_fcgi_request_completed++;
					if (err)
						dnet_fcgi_request_error++;
				} while (0);
			-1;
	});
	return err;
}

static int dnet_fcgi_upload(struct dnet_node *n, char *obj, int length, struct dnet_id *id,
		void *data, uint64_t size, int version, struct timespec *ts,
		int append)
{
	int trans_num = 0;
	uint32_t ioflags = 0;
	int err;
	struct timespec wait = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};
	char id_str[DNET_ID_SIZE*2+1];
	char obj_str[length + 1];
	char crc_str[2*DNET_ID_SIZE + 1];
	struct dnet_id raw;

	snprintf(obj_str, sizeof(obj_str), "%s", obj);

	dnet_transform(n, data, size, &raw);
	dnet_dump_id_len_raw(id->id, DNET_ID_SIZE, id_str);

	dnet_fcgi_post_len = snprintf(dnet_fcgi_post_buf, dnet_fcgi_post_buf_size,
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			"<post obj=\"%s\" id=\"%s\" crc=\"%s\" groups=\"%d\" size=\"%llu\">",
			obj_str, id_str,
			dnet_dump_id_len_raw(raw.id, DNET_ID_SIZE, crc_str),
			dnet_fcgi_group_num, (unsigned long long)size);

	dnet_fcgi_request_error = 0;
	dnet_fcgi_request_completed = 0;

	if (append)
		ioflags = DNET_IO_FLAGS_APPEND;

	err = dnet_common_write_object(n, id, NULL, 0, version != -1, data, size, version, ts,
			dnet_fcgi_upload_complete, NULL, ioflags);
	if (err > 0) {
		trans_num = err;
		err = dnet_create_write_metadata(n, id, obj, length, dnet_fcgi_groups, dnet_fcgi_group_num);
		if (err <= 0) {
			if (err == 0)
				err = -ENOENT;

			dnet_log_raw(n, DNET_LOG_ERROR, "%s: Failed to upload metadata: %d.\n", dnet_dump_id(id), err);
		}
	}
	dnet_log_raw(n, DNET_LOG_DSA, "Waiting for upload completion: %d/%d.\n", dnet_fcgi_request_completed, trans_num);

	err = dnet_fcgi_wait(dnet_fcgi_request_completed == trans_num, &wait);

	dnet_fcgi_post_len += snprintf(dnet_fcgi_post_buf + dnet_fcgi_post_len, dnet_fcgi_post_buf_size - dnet_fcgi_post_len,
			"<written>%d</written></post>\r\n",
			trans_num);

	dnet_fcgi_request_error += dnet_fcgi_group_num - trans_num;

	if (!err && dnet_fcgi_request_error > dnet_fcgi_tolerate_upload_error_count)
		err = -ENOENT;
	if (err) {
		dnet_fcgi_output("Cache-control: no-cache\r\n");
		dnet_fcgi_output("Reason: %s [%d]\r\n", strerror(-err), err);
		dnet_fcgi_output("Status: %d\r\n\r\n", 403);

		dnet_log_raw(n, DNET_LOG_ERROR, "%s: upload failed: err: %d, request_error: %d, tolerate_error_count: %d.\n",
				dnet_dump_id(id), err, dnet_fcgi_request_error, dnet_fcgi_tolerate_upload_error_count);
	} else {
		dnet_fcgi_output("Content-type: application/xml\r\n");
		dnet_fcgi_output("%s\r\n\r\n", dnet_fcgi_status_pattern);
	}

	dnet_fcgi_output("%s", dnet_fcgi_post_buf);

	/*
	 * We can not return error here, since we already wrote status.
	 */
	return 0;
}

static int dnet_fcgi_handle_post(struct dnet_node *n, char *obj, int length, struct dnet_id *id,
	int version, struct timespec *ts, int embed, int append)
{
	void *data = NULL;
	unsigned long data_size = 0, size;
	char *p;
	long err;

	if (dnet_fcgi_upload_host_limit) {
		int num = dnet_state_num(n);

		if (num < dnet_fcgi_upload_host_limit) {
			dnet_log_raw(n, DNET_LOG_ERROR, "Number of connected states (%d) is less than allowed in config for post (%d).\n",
				num, dnet_fcgi_upload_host_limit);
			return -ENOTCONN;
		}
	}

	p = FCGX_GetParam("CONTENT_LENGTH", dnet_fcgi_request.envp);
	if (p) {
		data_size = strtoul(p, NULL, 0);
		if (data_size > dnet_fcgi_max_request_size || !data_size) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: invalid content length: %lu, max: %lu.\n",
					dnet_dump_id(id), data_size, dnet_fcgi_max_request_size);
			goto err_out_exit;
		}

		size = data_size;
		if (embed)
			data_size += sizeof(struct dnet_fcgi_embed) * 2 + sizeof(uint64_t) * 2;

		data = malloc(data_size);
		if (!data) {
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to allocate %lu bytes.\n", dnet_dump_id(id), data_size);
			goto err_out_exit;
		}

		p = data;

		if (embed) {
			struct dnet_fcgi_embed *e = (struct dnet_fcgi_embed *)p;
			uint64_t *edata = (uint64_t *)e->data;

			e->size = sizeof(uint64_t) * 2;
			e->type = DNET_FCGI_EMBED_TIMESTAMP;
			e->flags = 0;
			dnet_fcgi_convert_embedded(e);

			edata[0] = dnet_bswap64(ts->tv_sec);
			edata[1] = dnet_bswap64(ts->tv_nsec);

			p += sizeof(struct dnet_fcgi_embed) + sizeof(uint64_t) * 2;
			e = (struct dnet_fcgi_embed *)p;

			e->size = size;
			e->type = DNET_FCGI_EMBED_DATA;
			e->flags = 0;
			dnet_fcgi_convert_embedded(e);

			p += sizeof(struct dnet_fcgi_embed);
		}

		while (size) {
			err = FCGX_GetStr(p, size, dnet_fcgi_request.in);
			if (err < 0 && errno != EAGAIN) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to read %lu bytes, total of %lu: %s [%d].\n",
						dnet_dump_id(id), size, data_size, strerror(errno), errno);
				goto err_out_free;
			}

			if (err == 0) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: short read: read_size: %lu, data_size: %lu, aborting.\n",
						dnet_dump_id(id), size, data_size);
				goto err_out_free;
			}

			p += err;
			size -= err;
		}
	}

	err = dnet_fcgi_upload(n, obj, length, id, data, data_size, version, ts, append);
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
		dnet_fcgi_log_write("No sign key, system will not authentificate users.\n");
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
		dnet_fcgi_log_write("Failed to initialize hash '%s': %d.\n", p, err);
		goto err_out_free;
	}

	p = getenv("DNET_FCGI_RANDOM_FILE");
	if (!p)
		p = DNET_FCGI_RANDOM_FILE;
	err = open(p, O_RDONLY);
	if (err < 0) {
		err = -errno;
		dnet_fcgi_log_write("Failed to open (read-only) random file '%s': %s [%d].\n",
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
		struct dnet_attr *a, void *priv)
{
	int err;
	struct dnet_node *n;
	struct dnet_io_attr *io;
	unsigned long long size;
	void *data;

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	n = dnet_get_node_from_state(st);

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	if (cmd->size <= sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr)) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: read completion error: wrong size: cmd_size: %llu, must be more than %zu.\n",
				dnet_dump_id(&cmd->id), (unsigned long long)cmd->size,
				sizeof(struct dnet_attr) + sizeof(struct dnet_io_attr));
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!a) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: no attributes but command size is not null.\n", dnet_dump_id(&cmd->id));
		err = -EINVAL;
		goto err_out_exit;
	}

	io = (struct dnet_io_attr *)(a + 1);
	data = io + 1;

	dnet_convert_io_attr(io);
	size = io->size;

	gettimeofday(&dnet_fcgi_read_time, NULL);

	/* received data embeds objects, potentially timestamp which we will hunt for here */
	if (priv) {
		while (size) {
			struct dnet_fcgi_embed *e = data;

			dnet_fcgi_convert_embedded(e);

			dnet_log_raw(n, DNET_LOG_ERROR, "%s: found embedded object: type: %x, flags: %x, size: %llu, rest: %llu.\n",
					dnet_dump_id(&cmd->id), e->type, e->flags, (unsigned long long)e->size,
					(unsigned long long)size);

			if (size < e->size + sizeof(struct dnet_fcgi_embed)) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: broken embedded object: e->size(%llu) + "
						"embed-struct-size(%zu) > data-size(%llu).\n",
						dnet_dump_id(&cmd->id), (unsigned long long)e->size,
						sizeof(struct dnet_fcgi_embed), size);
				err = -EINVAL;
				goto err_out_exit;
			}

			if (e->type == DNET_FCGI_EMBED_TIMESTAMP) {
				uint64_t *ptr = (uint64_t *)e->data;

				dnet_fcgi_trans_tsec = dnet_bswap64(ptr[0]);
				/* dnet_fcgi_trans_nsec = dnet_bswap64(ptr[1]); */
			}

			data += sizeof(struct dnet_fcgi_embed);
			size -= sizeof(struct dnet_fcgi_embed);

			if (e->type == DNET_FCGI_EMBED_DATA) {
				size = e->size;
				break;
			}

			data += e->size;
			size -= e->size;
		}
	}

	err = dnet_fcgi_put_last_modified();
	if (err) {
		if (err > 0)
			err = 0;
		goto err_out_exit;
	}

	dnet_fcgi_output("\r\n");

	pthread_mutex_lock(&dnet_fcgi_output_lock);

	if (!dnet_fcgi_request_info) {
		err = -EBADF;
		goto err_out_unlock;
	}

	while (size) {
		err = FCGX_PutStr(data, size, dnet_fcgi_request.out);
		if (err < 0 && errno != EAGAIN) {
			err = -errno;
			dnet_log_raw(n, DNET_LOG_ERROR, "%s: failed to write %llu bytes, "
					"total of %llu: %s [%d].\n",
					dnet_dump_id(&cmd->id), size, (unsigned long long)io->size,
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
		if (cmd && state)
			dnet_log_raw(dnet_get_node_from_state(state), DNET_LOG_ERROR,
					"state: %p, cmd: %p, err: %d.\n", state, cmd, cmd->status);
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

/* I'm a small hack, do not look at me */
static pthread_mutex_t dnet_fcgi_stat_lock = PTHREAD_MUTEX_INITIALIZER;

static int dnet_fcgi_stat_complete_log(struct dnet_net_state *state,
	struct dnet_cmd *cmd, struct dnet_attr *attr, void *priv)
{
	if (!state || !cmd || !attr)
		goto out;

	pthread_mutex_lock(&dnet_fcgi_stat_lock);
	if (attr->size == sizeof(struct dnet_stat) && attr->cmd == DNET_CMD_STAT) {
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
				dnet_dump_id_len_raw(cmd->id.id, DNET_ID_SIZE, id),
				la[0], la[1], la[2],
				(unsigned long long)st->vm_total,
				(unsigned long long)st->vm_free,
				(unsigned long long)st->vm_cached,
				(unsigned long long)(st->frsize * st->blocks / 1024 / 1024),
				(unsigned long long)(st->bavail * st->bsize / 1024 / 1024),
				(unsigned long long)st->files, (unsigned long long)st->fsid);
	} else if (attr->size >= sizeof(struct dnet_addr_stat) && attr->cmd == DNET_CMD_STAT_COUNT) {
		struct dnet_addr_stat *as = (struct dnet_addr_stat *)(attr + 1);
		char addr[128];
		int i;

		dnet_convert_addr_stat(as, 0);

		dnet_fcgi_output("<count addr=\"%s\">",
			dnet_server_convert_dnet_addr_raw(&as->addr, addr, sizeof(addr)));
		for (i=0; i<as->num; ++i)
			dnet_fcgi_output("<counter cmd=\"%u\" count=\"%llu\" error=\"%llu\"/>", i,
					(unsigned long long)as->count[i].count, (unsigned long long)as->count[i].err);
		dnet_fcgi_output("</count>");
	}
	pthread_mutex_unlock(&dnet_fcgi_stat_lock);

out:
	return dnet_fcgi_stat_complete(state, cmd, attr, priv);
}

static int dnet_fcgi_request_stat(struct dnet_node *n,
	int (* complete)(struct dnet_net_state *state,
			struct dnet_cmd *cmd,
			struct dnet_attr *attr,
			void *priv))
{
	int err, num = 0;
	struct timespec ts = {.tv_sec = dnet_fcgi_timeout_sec, .tv_nsec = 0};

	dnet_fcgi_stat_good = dnet_fcgi_stat_bad = 0;
	dnet_fcgi_request_completed = 0;

	err = dnet_request_stat(n, NULL, DNET_CMD_STAT, complete, NULL);
	if (err < 0) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to request stat: %d.\n", err);
		goto err_out_exit;
	}
	num += err;

#if 0
	err = dnet_request_stat(n, NULL, DNET_CMD_STAT_COUNT, complete, NULL);
	if (err < 0) {
		dnet_log_raw(n, DNET_LOG_ERROR, "Failed to request stat: %d.\n", err);
		goto err_out_wait;
	}
	num += err;

err_out_wait:
#endif
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
	int num = dnet_state_num(n);
	int err = 0;

	if (num < dnet_fcgi_stat_bad_limit) {
		err = -ENOTCONN;
		dnet_fcgi_output("\r\nStatus: 400\r\n\r\n");
	} else
		dnet_fcgi_output("\r\n%s\r\n\r\n", dnet_fcgi_status_pattern);

	return err;
}

static int dnet_fcgi_external_start(struct dnet_node *n, char *query, char *addr, char *id, int length)
{
	int err;

	err = dnet_fcgi_external_callback_start(query, addr, id, length);
	if (err < 0) {
		dnet_log_raw(n, DNET_LOG_ERROR, "q: '%s', failed to determine region for addr '%s': %d.\n",
				query, addr, err);
		return err;
	}

	dnet_fcgi_region = err;
	return 0;
}

static int dnet_fcgi_external_stop(struct dnet_node *n __unused, char *query, char *addr, char *id, int length)
{
	return dnet_fcgi_external_callback_stop(query, addr, id, length);
}

static void dnet_fcgi_output_content_type(char *obj)
{
	int i;
	struct dnet_fcgi_content_type *c;

	for (i=0; i<dnet_fcgi_ctypes_num; ++i) {
		c = &dnet_fcgi_ctypes[i];

		if (strcasestr(obj, c->ext)) {
			dnet_fcgi_output("Content-type: %s\r\n", c->type);
			return;
		}
	}
	
	dnet_fcgi_output("Content-type: octet/stream\r\n");
}

static int dnet_fcgi_handle_get(struct dnet_node *n, char *query, char *obj, int length, struct dnet_id *id,
		int version, int embed, int multiple)
{
	int err;
	char *p;
	struct dnet_io_control ctl, *c = NULL;

	if (dnet_fcgi_direct_download) {
		int i = 0;

		p = strstr(query, dnet_fcgi_direct_download);
		if (!p)
			goto lookup;

		if (!dnet_fcgi_direct_download_all) {
			for (i=0; i<dnet_fcgi_direct_patterns_num; ++i) {
				char *pattern = dnet_fcgi_direct_patterns[i];
				int len = strlen(pattern);

				if (length < len)
					continue;

				if (!strncmp(obj + length - len, pattern, len))
					break;
			}
		}

		if (dnet_fcgi_direct_download_all || (i != dnet_fcgi_direct_patterns_num)) {
			memset(&ctl, 0, sizeof(struct dnet_io_control));

			dnet_fcgi_output_content_type(obj);

			memcpy(&ctl.id, id, sizeof(struct dnet_id));

			ctl.fd = -1;
			ctl.complete = dnet_fcgi_read_complete;
			ctl.cmd = DNET_CMD_READ;
			ctl.cflags = DNET_FLAGS_NEED_ACK;
			ctl.priv = (void *)(unsigned long)embed;

			c = &ctl;
		} else {
			/*
			 * Do not try non-direct download if
			 * unsupported type was requested.
			 */

			err = -EPERM;
			goto out_exit;
		}
	}

lookup:
	err = dnet_fcgi_process_io(n, id, c, version, embed, multiple);
	if (err) {
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: lookup/read failed : %d.\n", dnet_dump_id(id), err);
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

		dnet_fcgi_log_write("%s -> %s\n", c->ext, c->type);
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
		dnet_fcgi_log_write("Failed to load external library '%s': %s.\n",
				name, dlerror());
		goto err_out_exit;
	}

	dnet_fcgi_external_callback_start = dlsym(lib, DNET_FCGI_EXTERNAL_CALLBACK_START);
	if (!dnet_fcgi_external_callback_start) {
		dnet_fcgi_log_write("Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_CALLBACK_START, name);
		goto err_out_close;
	}

	dnet_fcgi_external_callback_stop = dlsym(lib, DNET_FCGI_EXTERNAL_CALLBACK_STOP);
	if (!dnet_fcgi_external_callback_stop) {
		dnet_fcgi_log_write("Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_CALLBACK_STOP, name);
		goto err_out_null;
	}

	init = dlsym(lib, DNET_FCGI_EXTERNAL_INIT);
	if (!init) {
		dnet_fcgi_log_write("Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_INIT, name);
		goto err_out_null;
	}

	dnet_fcgi_external_exit = dlsym(lib, DNET_FCGI_EXTERNAL_EXIT);
	if (!dnet_fcgi_external_exit) {
		dnet_fcgi_log_write("Failed to get '%s' symbol from external library '%s'.\n",
				DNET_FCGI_EXTERNAL_EXIT, name);
		goto err_out_null;
	}

	data = getenv("DNET_FCGI_EXTERNAL_DATA");
	err = init(data);
	if (err) {
		dnet_fcgi_log_write("Failed to initialize external library '%s' using data '%s'.\n",
				name, data);
		goto err_out_null;
	}

	dnet_fcgi_log_write("Successfully initialized external library '%s' using data '%s'.\n",
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

		dnet_fcgi_log_write("Added '%s' permanent header.\n", token);

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

static void dnet_fcgi_destroy_permanent_headers(void)
{
	int i;

	for (i=0; i<dnet_fcgi_pheaders_num; ++i)
		free(dnet_fcgi_pheaders[i]);

	free(dnet_fcgi_pheaders);
	dnet_fcgi_pheaders_num = 0;
}

static void dnet_setup_params(void)
{
	char *p;

	dnet_fcgi_setup_permanent_headers();

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

	p = getenv("DNET_FCGI_PUT_REGION");
	if (p)
		dnet_fcgi_put_region = atoi(p);

	p = getenv("DNET_FCGI_USE_LA");
	if (p)
		dnet_fcgi_use_la_check = atoi(p);

	p = getenv("DNET_FCGI_DNS_LOOKUP");
	if (p)
		dnet_fcgi_dns_lookup = atoi(p);

	p = getenv("DNET_FCGI_UPLOAD_HOST_LIMIT");
	if (p)
		dnet_fcgi_upload_host_limit = atoi(p);

	p = getenv("DNET_FCGI_TOLERATE_UPLOAD_ERROR_COUNT");
	if (p)
		dnet_fcgi_tolerate_upload_error_count = atoi(p);

	p = getenv("DNET_FCGI_CONTENT_TYPES");
	if (p)
		dnet_fcgi_setup_content_type_patterns(p);

	p = getenv("DNET_FCGI_ADDR_HEADER");
	if (p)
		dnet_fcgi_remote_addr_header = p;

	p = getenv("DNET_FCGI_EXTERNAL_LIB");
	if (p)
		dnet_fcgi_setup_external_callbacks(p);

	p = getenv("DNET_FCGI_LAST_MODIFIED");
	if (p)
		dnet_fcgi_last_modified = atoi(p);

	p = getenv("DNET_FCGI_STORAGE_BITS");
	if (p)
		dnet_fcgi_bit_num = ALIGN(atoi(p), 4);

	dnet_fcgi_post_allowed = 0;
	p = getenv("DNET_FCGI_POST_ALLOWED");
	if (p)
		dnet_fcgi_post_allowed = atoi(p);

}

static int dnet_fcgi_get_groups(struct dnet_node *n, char *q, struct dnet_id *id, int **groupsp)
{
	struct dnet_id_param *ids;
	int *groups;
	int err, group_num, i, start;
	char *p, *query;

	query = strdup(q);
	if (!query) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	p = strstr(query, dnet_fcgi_groups_pattern);
	if (!p) {
		err = -ENOENT;
		goto err_out_free;
	}

	p += dnet_fcgi_groups_pattern_len;
	if (!p || !*p) {
		err = -EINVAL;
		goto err_out_free;
	}

	err = dnet_parse_groups(p, groupsp);
	if (err <= 0)
		goto err_out_free;

	if (*groupsp)
		goto err_out_free;
	group_num = err;

	groups = malloc(sizeof(int) * group_num);
	if (!groups) {
		err = -ENOMEM;
		goto err_out_free;
	}

	err = dnet_generate_ids_by_param(n, id, DNET_ID_PARAM_FREE_SPACE, &ids);
	if (err <= 0)
		goto err_out_free_groups;

	start = 0;
	for (i=0; i<group_num; ++i) {
		if (i < err) {
			groups[i] = ids[err - i - 1].group_id;
			if (groups[i] > start)
				start = groups[i];
		} else {
			groups[i] = start + i;
		}

		dnet_log_raw(n, DNET_LOG_DSA, "%s: selected groups: %d\n", dnet_dump_id(id), groups[i]);
	}

	free(ids);
	*groupsp = groups;
	return group_num;

err_out_free_groups:
	free(groups);
err_out_free:
	free(query);
err_out_exit:
	return err;
}

int main()
{
	char *p, *addr, *reason, *method, *query;
	char *id_pattern, *id_delimiter, *direct_patterns = NULL, *version_pattern, *version_str, *timestamp_pattern, *embed_pattern, *embed_str;
	char *multiple_pattern, *append_pattern;
	int length, id_pattern_length, err, version_pattern_len, timestamp_pattern_len, multiple_pattern_len;
	struct timeval tstart, tend;
	long tdiff, iodiff;
	int version;
	char *obj, *end;
	struct dnet_config cfg;
	struct dnet_node *n;
	struct dnet_id raw;
	int *tmp_groups, tmp_group_num;
	int *groups, group_num;

	p = getenv("DNET_FCGI_LOG");
	if (!p)
		p = DNET_FCGI_LOG;

	if (!strcmp(p, "syslog")) {
		openlog("fcgi", LOG_PID, LOG_USER);
	} else {
		dnet_fcgi_log = fopen(p, "a");
		if (!dnet_fcgi_log) {
			err = -errno;
			fprintf(stderr, "Failed to open '%s' log file.\n", p);
			goto err_out_exit;
		}
	}

	dnet_setup_params();

	p = getenv("DNET_FCGI_BASE_PORT");
	if (!p) {
		err = -ENOENT;
		dnet_fcgi_log_write("No DNET_FCGI_BASE_PORT provided, I will not be able to determine proper directory to fetch objects.\n");
		goto err_out_close;
	}
	dnet_fcgi_base_port = atoi(p);

	dnet_fcgi_unlink_pattern = getenv("DNET_FCGI_UNLINK_PATTERN_URI");
	dnet_fcgi_stat_pattern = getenv("DNET_FCGI_STAT_PATTERN_URI");
	p = getenv("DNET_FCGI_STAT_BAD_LIMIT");
	if (p)
		dnet_fcgi_stat_bad_limit = atoi(p);
	dnet_fcgi_stat_log_pattern = getenv("DNET_FCGI_STAT_LOG_PATTERN_URI");

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

				if ((strlen(token) == 1) && (*token == DNET_FCGI_TOKEN_DIRECT_ALL)) {
					dnet_fcgi_direct_download_all = 1;
					dnet_fcgi_log_write("Added 'allow-all' direct download pattern.\n");
				} else {
					dnet_fcgi_direct_patterns_num++;
					dnet_fcgi_direct_patterns = realloc(dnet_fcgi_direct_patterns,
							dnet_fcgi_direct_patterns_num * sizeof(char *));
					if (!dnet_fcgi_direct_patterns) {
						err = -ENOMEM;
						goto err_out_free_direct_patterns;
					}

					dnet_fcgi_direct_patterns[dnet_fcgi_direct_patterns_num - 1] = token;
					dnet_fcgi_log_write("Added '%s' direct download pattern.\n", token);
				}

				tmp = NULL;
			}
		}
	}

	err = dnet_fcgi_fill_config(&cfg);
	if (err) {
		dnet_fcgi_log_write("Failed to parse config.\n");
		goto err_out_free_direct_patterns;
	}

	err = dnet_fcgi_setup_sign_hash();
	if (err)
		goto err_out_close;
	
	cfg.log->log(cfg.log->log_private, DNET_LOG_ERROR, "test\n\n");

	n = dnet_node_create(&cfg);
	if (!n)
		goto err_out_sign_destroy;

	addr = getenv("DNET_FCGI_REMOTE_ADDR");
	if (!addr) {
		dnet_fcgi_log_write("No remote address specified, aborting.\n");
		err = -ENOENT;
		goto err_out_free;
	}

	err = dnet_common_add_remote_addr(n, &cfg, addr);
	if (err)
		goto err_out_free;

	p = getenv("DNET_FCGI_GROUPS");
	if (!p) {
		dnet_fcgi_log_write("No groups specified, aborting.\n");
		err = -ENODEV;
		goto err_out_free;
	}
	dnet_fcgi_group_num = dnet_parse_groups(p, &dnet_fcgi_groups);
	if (dnet_fcgi_group_num <= 0) {
		dnet_fcgi_log_write("Invalid groups specified: '%s', aborting.\n", p);
		err = -EINVAL;
		goto err_out_free;
	}

	dnet_node_set_groups(n, dnet_fcgi_groups, dnet_fcgi_group_num);

	p = getenv("DNET_FCGI_GROUPS_PATTERN");
	if (p)
		dnet_fcgi_groups_pattern = p;
	dnet_fcgi_groups_pattern_len = strlen(dnet_fcgi_groups_pattern);

	dnet_fcgi_post_buf_size = (dnet_fcgi_group_num + 1) * 1024;
	dnet_fcgi_post_buf = malloc(dnet_fcgi_post_buf_size);
	if (!dnet_fcgi_post_buf) {
		err = -ENOMEM;
		goto err_out_free;
	}

	p = getenv("DNET_FCGI_TMP_DIR");
	if (!p)
		p = DNET_FCGI_TMP_DIR;
	dnet_fcgi_tmp_dir = strdup(p);
	if (!dnet_fcgi_tmp_dir) {
		err = -ENOMEM;
		goto err_out_free;
	}
	dnet_fcgi_tmp_dir_len = strlen(dnet_fcgi_tmp_dir);

	id_pattern = getenv("DNET_FCGI_ID_PATTERN");
	id_delimiter = getenv("DNET_FCGI_ID_DELIMITER");
	version_pattern = getenv("DNET_FCGI_VERSION_PATTERN");
	timestamp_pattern = getenv("DNET_FCGI_TIMESTAMP_PATTERN");
	append_pattern = getenv("DNET_FCGI_APPEND_PATTERN");
	embed_pattern = getenv("DNET_FCGI_EMBED_PATTERN");
	multiple_pattern = getenv("DNET_FCGI_MULTIPLE_PATTERN");

	if (!id_pattern)
		id_pattern = DNET_FCGI_ID_PATTERN;
	if (!id_delimiter)
		id_delimiter = DNET_FCGI_ID_DELIMITER;
	if (!version_pattern)
		version_pattern = DNET_FCGI_VERSION_PATTERN;
	version_pattern_len = strlen(version_pattern);

	if (!append_pattern)
		append_pattern = DNET_FCGI_APPEND_PATTERN;
	if (!timestamp_pattern)
		timestamp_pattern = DNET_FCGI_TIMESTAMP_PATTERN;
	timestamp_pattern_len = strlen(timestamp_pattern);

	if (!embed_pattern)
		embed_pattern = DNET_FCGI_EMBED_PATTERN;
	
	if (!multiple_pattern)
		multiple_pattern = DNET_FCGI_MULTIPLE_PATTERN;
	multiple_pattern_len = strlen(multiple_pattern);

	id_pattern_length = strlen(id_pattern);

	err = FCGX_Init();
	if (err) {
		dnet_fcgi_log_write("FCGX initaliation failed: %d.\n", err);
		goto err_out_free_tmp_dir;
	}

	err = FCGX_InitRequest(&dnet_fcgi_request, LISTENSOCK_FILENO, LISTENSOCK_FLAGS);
	if (err) {
		dnet_fcgi_log_write("FCGX request initaliation failed: %d.\n", err);
		goto err_out_fcgi_exit;
	}

	while (1) {
		err = FCGX_Accept_r(&dnet_fcgi_request);
		if (err || !dnet_fcgi_request.in || !dnet_fcgi_request.out || !dnet_fcgi_request.err || !dnet_fcgi_request.envp) {
			dnet_log_raw(n, DNET_LOG_ERROR, "Failed to accept client: no IO streams: in: %p, out: %p, err: %p, env: %p, err: %d.\n",
					dnet_fcgi_request.in, dnet_fcgi_request.out, dnet_fcgi_request.err, dnet_fcgi_request.envp, err);
			continue;
		}

		pthread_mutex_lock(&dnet_fcgi_output_lock);
		dnet_fcgi_request_info = 1;
		pthread_mutex_unlock(&dnet_fcgi_output_lock);

		addr = FCGX_GetParam(dnet_fcgi_remote_addr_header, dnet_fcgi_request.envp);
		if (!addr) {
			addr = FCGX_GetParam(DNET_FCGI_ADDR_HEADER, dnet_fcgi_request.envp);
			if (!addr)
				continue;
		}

		tmp_groups = NULL;
		tmp_group_num = 0;

		groups = NULL;
		group_num = 0;

		version = -1;
		embed_str = NULL;

		method = FCGX_GetParam("REQUEST_METHOD", dnet_fcgi_request.envp);
		obj = NULL;
		length = 0;

		err = -EINVAL;
		query = p = FCGX_GetParam("QUERY_STRING", dnet_fcgi_request.envp);
		if (!p) {
			reason = "no query string";
			goto err_continue;
		}

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

		dnet_log_raw(n, DNET_LOG_DSA, "query: '%s'.\n", query);
		gettimeofday(&tstart, NULL);

		p = query;
		obj = strstr(p, id_pattern);
		if (!obj) {
			reason = "malformed request, no id part";
			goto err_continue;
		}

		obj += id_pattern_length;
		if (!*obj) {
			reason = "malformed request, no id part";
			goto err_continue;
		}

		end = strstr(obj, id_delimiter);
		if (!end)
			end = obj + strlen(obj);

		length = end - obj;

		dnet_transform(n, obj, length, &raw);
		memcpy(dnet_fcgi_id, raw.id, DNET_ID_SIZE);
		raw.group_id = 0;

		version_str = strstr(query, version_pattern);
		if (version_str) {
			version_str += version_pattern_len;
			if (*version_str)
				version = strtol(version_str, NULL, 0);
		}

		embed_str = strstr(query, embed_pattern);

		if (dnet_fcgi_groups_pattern) {
			tmp_groups = dnet_fcgi_groups;
			tmp_group_num = dnet_fcgi_group_num;

			dnet_fcgi_groups = NULL;
			dnet_fcgi_group_num = 0;

			dnet_node_set_groups(n, NULL, 0);

			err = dnet_fcgi_get_groups(n, query, &raw, &groups);
			if (err > 0) {
				group_num = err;

				dnet_fcgi_groups = groups;
				dnet_fcgi_group_num = group_num;
				dnet_node_set_groups(n, groups, group_num);
			} else {
				dnet_fcgi_groups = tmp_groups;
				dnet_fcgi_group_num = tmp_group_num;
				dnet_node_set_groups(n, dnet_fcgi_groups, dnet_fcgi_group_num);

				tmp_groups = NULL;
				tmp_group_num = 0;
			}
		}

		if (dnet_fcgi_external_callback_start)
			dnet_fcgi_external_start(n, query, addr, obj, length);

		dnet_fcgi_output_permanent_headers();

		dnet_fcgi_read_time.tv_sec = 0;

		if (!strncmp(method, "POST", 4)) {
			struct timespec ts;
			int append;
			char *ts_str;

			if (!dnet_fcgi_post_allowed) {
				err = -EACCES;
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: POST is not allowed for object '%s'.\n", addr, obj);
				reason = "POST is not allowed";
				goto err_continue;
			}
			append = !!strstr(query, append_pattern);

			ts_str = strstr(query, timestamp_pattern);
			if (ts_str) {
				ts_str += timestamp_pattern_len;
				if (*ts_str) {
					ts.tv_sec = strtoul(ts_str, NULL, 0);
					ts.tv_nsec = 0;
				}
			} else {
				struct timeval tv;

				gettimeofday(&tv, NULL);

				ts.tv_sec = tv.tv_sec;
				ts.tv_nsec = tv.tv_usec * 1000;
			}

			dnet_log_raw(n, DNET_LOG_INFO, "%s: obj: '%s', len: %d, v: %d, ts: %lu.%lu, embed: %d, region: %d, append: %d.\n",
					dnet_dump_id(&raw), obj, length, version, ts.tv_sec, ts.tv_nsec, !!embed_str, dnet_fcgi_region, append);

			err = dnet_fcgi_handle_post(n, obj, length, &raw, version, &ts, !!embed_str, append);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: Failed to handle POST for object '%s': %d.\n", addr, obj, err);
				goto cont;
			}
		} else if (dnet_fcgi_unlink_pattern && strstr(query, dnet_fcgi_unlink_pattern)) {
			err = dnet_fcgi_unlink(n, &raw, version);
		} else {
			int multiple = 0;
			char *multiple_str;

			multiple_str = strstr(query, multiple_pattern);
			if (multiple_str) {
				multiple_str += multiple_pattern_len;
				if (*multiple_str)
					multiple = atoi(multiple_str);
			}

			dnet_log_raw(n, DNET_LOG_INFO, "%s: obj: '%s', len: %d, v: %d, embed: %d, region: %d, mult: %d.\n",
					dnet_dump_id(&raw), obj, length, version, !!embed_str, dnet_fcgi_region, multiple);
			err = dnet_fcgi_handle_get(n, query, obj, length, &raw, version, !!embed_str, multiple);
			if (err) {
				dnet_log_raw(n, DNET_LOG_ERROR, "%s: Failed to handle GET for object '%s': %d.\n", addr, obj, err);
				reason = "failed to handle GET";
				goto err_continue;
			}
		}

cont:
		if (tmp_groups && tmp_group_num) {
			dnet_fcgi_groups = tmp_groups;
			dnet_fcgi_group_num = tmp_group_num;
			dnet_node_set_groups(n, dnet_fcgi_groups, dnet_fcgi_group_num);

			free(groups);
		}
		dnet_fcgi_region = -1;
		if (dnet_fcgi_external_callback_stop)
			dnet_fcgi_external_stop(n, query, addr, obj, length);

		pthread_mutex_lock(&dnet_fcgi_output_lock);
		FCGX_Finish_r(&dnet_fcgi_request);
		dnet_fcgi_request_info = 0;
		pthread_mutex_unlock(&dnet_fcgi_output_lock);

		gettimeofday(&tend, NULL);

		tdiff = (tend.tv_sec - tstart.tv_sec) * 1000 + tend.tv_usec - tstart.tv_usec;
		iodiff = -1;
		if (dnet_fcgi_read_time.tv_sec) {
			iodiff = (dnet_fcgi_read_time.tv_sec - tstart.tv_sec) * 1000 + dnet_fcgi_read_time.tv_usec - tstart.tv_usec;
		}

		dnet_log_raw(n, DNET_LOG_INFO, "%s: completed: obj: '%s', len: %d, v: %d, embed: %d, region: %d, err: %d, total time: %lu usecs, read io time: %ld usecs.\n",
					dnet_dump_id(&raw), obj, length, version, !!embed_str, dnet_fcgi_region, err, tdiff, iodiff);
		continue;

err_continue:
		dnet_fcgi_output("Cache-control: no-cache\r\n");
		dnet_fcgi_output("Content-Type: text/plain\r\n");
		dnet_fcgi_output("Status: %d\r\n\r\n", (err == -ENOENT) ? 404 : 403);
		dnet_fcgi_output("Reason: %s: %s [%d]\r\n", reason, strerror(-err), err);
		if (query)
			dnet_fcgi_output("Query: %s\r\n", query);
		dnet_log_raw(n, DNET_LOG_ERROR, "%s: bad request: %s: %s [%d]\n", addr, reason, strerror(-err), err);
		goto cont;
	}

	dnet_node_destroy(n);
	dnet_fcgi_destroy_sign_hash();

	free(direct_patterns);
	free(dnet_fcgi_direct_patterns);
	dnet_fcgi_destroy_permanent_headers();

	if (dnet_fcgi_external_exit)
		dnet_fcgi_external_exit();

	if (dnet_fcgi_log)
		fclose(dnet_fcgi_log);
	else
		closelog();

	return 0;

err_out_fcgi_exit:
	FCGX_ShutdownPending();
err_out_free_tmp_dir:
	free(dnet_fcgi_tmp_dir);
err_out_free:
	dnet_node_destroy(n);
	free(dnet_fcgi_post_buf);
err_out_sign_destroy:
	dnet_fcgi_destroy_sign_hash();
err_out_free_direct_patterns:
	free(direct_patterns);
	free(dnet_fcgi_direct_patterns);
err_out_close:
	fflush(dnet_fcgi_log);
	fclose(dnet_fcgi_log);
	dnet_fcgi_destroy_permanent_headers();
err_out_exit:
	return err;
}
