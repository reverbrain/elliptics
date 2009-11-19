#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>

#include "dnet/packet.h"
#include "dnet/interface.h"

#include "hash.h"
#include "common.h"

#define NO_FCGI_DEFINES
#include <fcgi_stdio.h>

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

#define FCGI_DNET_ID_PATTERN		"id="
#define FCGI_DNET_ID_DELIMITER		"&"
#define FCGI_DNET_LOG			"/tmp/dnet_fcgi.log"
#define FCGI_DNET_LOCAL_ADDR		"0.0.0.0:1025:2"
#define FCGI_DNET_SUCCESS_STATUS_PATTERN	"Status: 301"
#define FCGI_DNET_ROOT_PATTERN		""
#define DNET_FCGI_MAX_REQUEST_SIZE	(100*1024*1024)

static FILE *dnet_fcgi_log;
static pthread_cond_t dnet_fcgi_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dnet_fcgi_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int dnet_fcgi_request_completed, dnet_fcgi_request_init_value = 11223344;
static char *dnet_fcgi_status_pattern, *dnet_fcgi_root_pattern;
static unsigned long dnet_fcgi_max_request_size;
static int dnet_fcgi_base_port;

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

	p = getenv("FCGI_DNET_NODE_ID");
	if (p) {
		err = dnet_parse_numeric_id(p, cfg->id);
		if (err)
			return err;
	}

	p = getenv("FCGI_DNET_NODE_LOG_MASK");
	if (p)
		cfg->log_mask = strtoul(p, NULL, 0);

	p = getenv("FCGI_DNET_NODE_WAIT_TIMEOUT");
	if (p)
		cfg->wait_timeout = strtoul(p, NULL, 0);

	p = getenv("FCGI_DNET_NODE_LOCAL_ADDR");
	if (!p)
		p = FCGI_DNET_LOCAL_ADDR;

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

	addr = getenv("FCGI_DNET_REMOTE_ADDR");
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
	char *h, *hash, *p;
	int added = 0, err;
	struct dnet_crypto_engine *e;

	hash = getenv("FCGI_DNET_HASH");
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

		e = malloc(sizeof(struct dnet_crypto_engine));
		if (!e) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		memset(e, 0, sizeof(struct dnet_crypto_engine));

		err = dnet_crypto_engine_init(e, hash);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to initialize hash '%s': %d.\n", hash, err);
			goto err_out_exit;
		}

		err = dnet_add_transform(n, e, e->name,	e->init, e->update, e->final);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to add hash '%s': %d.\n", hash, err);
			goto err_out_exit;
		}

		fprintf(dnet_fcgi_log, "Added hash '%s'.\n", hash);
		added++;

		if (!p)
			break;

		hash = p;

		while (hash && *hash && isspace(*hash))
			hash++;
	}
	free(h);

	if (!added) {
		err = -ENOENT;
		fprintf(dnet_fcgi_log, "No remote hashes added, aborting.\n");
		goto err_out_exit;
	}

	return 0;

err_out_exit:
	return err;
}

#define dnet_fcgi_wait(condition)						\
({										\
	pthread_mutex_lock(&dnet_fcgi_wait_lock);				\
	while (!(condition))							\
		pthread_cond_wait(&dnet_fcgi_cond, &dnet_fcgi_wait_lock);	\
	pthread_mutex_unlock(&dnet_fcgi_wait_lock);				\
})

static void dnet_fcgi_wakeup(int err)
{
	pthread_mutex_lock(&dnet_fcgi_wait_lock);
	dnet_fcgi_request_completed = err;
	pthread_cond_broadcast(&dnet_fcgi_cond);
	pthread_mutex_unlock(&dnet_fcgi_wait_lock);
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

		fprintf(dnet_fcgi_log, "%s: addr: %s, is object presented there: %d.\n",
				dnet_dump_id(cmd->id),
				dnet_server_convert_dnet_addr(&a->addr),
				attr->flags);

		err = -EAGAIN;
		if (attr->flags) {
			char id[DNET_ID_SIZE*2+1];
			int port = dnet_server_convert_port((struct sockaddr *)a->addr.addr, a->addr.addr_len);

			snprintf(id, sizeof(id), "%s", dnet_dump_id_len(cmd->id, DNET_ID_SIZE));

			FCGI_printf("%s\r\n", dnet_fcgi_status_pattern);
			FCGI_printf("Location: http://%s%s/%d/%02x/%s\r\n",
					dnet_state_dump_addr_only(&a->addr),
					dnet_fcgi_root_pattern,
					port - dnet_fcgi_base_port,
					cmd->id[0], id);

			FCGI_printf("Content-type: application/xml\r\n");
			FCGI_printf("\r\n\r\n");
			FCGI_printf("<data id=\"%s\" url=\"http://%s%s/%d/%02x/%s\"/>", id,
					dnet_state_dump_addr_only(&a->addr),
					dnet_fcgi_root_pattern,
					port - dnet_fcgi_base_port,
					cmd->id[0], id);

			fprintf(dnet_fcgi_log, "%s -> http://%s%s/%02x/%s\n",
					dnet_fcgi_status_pattern,
					dnet_state_dump_addr_only(&a->addr),
					dnet_fcgi_root_pattern,
					cmd->id[0], id);
			err = 0;
		}

		dnet_fcgi_wakeup(err);
	}

	if (cmd->status || !cmd->size) {
		err = cmd->status;
		goto err_out_exit;
	}

	return err;

err_out_exit:
	dnet_fcgi_wakeup(err);
	return err;
}

static int dnet_fcgi_lookup(struct dnet_node *n, char *obj, int len)
{
	unsigned char origin[DNET_ID_SIZE], addr[DNET_ID_SIZE];
	int err, error = -ENOENT;
	int pos = 0;

	while (1) {
		unsigned int rsize = DNET_ID_SIZE;

		err = dnet_transform(n, obj, len, origin, addr, &rsize, &pos);
		if (err) {
			if (err > 0)
				break;
			continue;
		}

		dnet_fcgi_request_completed = dnet_fcgi_request_init_value;

		err = dnet_lookup_object(n, origin, 1, dnet_fcgi_lookup_complete, NULL);
		if (err) {
			error = err;
			continue;
		}

		dnet_fcgi_wait(dnet_fcgi_request_completed != dnet_fcgi_request_init_value);

		if (dnet_fcgi_request_completed < 0) {
			error = dnet_fcgi_request_completed;
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

	if (!cmd || !st) {
		err = -EINVAL;
		goto err_out_exit;
	}

	if (!(cmd->flags & DNET_FLAGS_MORE)) {
		dnet_fcgi_wakeup(dnet_fcgi_request_completed + 1);
		fprintf(dnet_fcgi_log, "%s: upload completed: %d.\n",
				dnet_dump_id(cmd->id), dnet_fcgi_request_completed);
	}

	if (cmd->status) {
		err = cmd->status;
		goto err_out_exit;
	}


err_out_exit:
	return err;
}

static int dnet_fcgi_upload(struct dnet_node *n, char *addr, char *obj, void *data, uint64_t size)
{
	struct dnet_io_control ctl;
	int trans_num = 0;
	int err;

	memset(&ctl, 0, sizeof(struct dnet_io_control));

	ctl.data = data;
	ctl.fd = -1;

	ctl.complete = dnet_fcgi_upload_complete;
	ctl.priv = NULL;

	ctl.cflags = DNET_FLAGS_NEED_ACK;
	ctl.cmd = DNET_CMD_WRITE;
	ctl.aflags = DNET_ATTR_DIRECT_TRANSACTION | DNET_ATTR_NO_TRANSACTION_SPLIT;

	ctl.io.flags = DNET_IO_FLAGS_NO_HISTORY_UPDATE;
	ctl.io.size = size;
	ctl.io.offset = 0;

	dnet_fcgi_request_completed = 0;
	err = dnet_write_object(n, &ctl, obj, NULL, 0, &trans_num);
	if (err < 0) {
		fprintf(dnet_fcgi_log, "%s: failed to upload '%s' object: %d.\n", addr, obj, err);
		goto err_out_exit;
	}

	err = 0;

	fprintf(dnet_fcgi_log, "%s: waiting for upload completion: %d/%d.\n", addr, dnet_fcgi_request_completed, trans_num);
	dnet_fcgi_wait(dnet_fcgi_request_completed == trans_num);

err_out_exit:
	return err;
}

static int dnet_fcgi_handle_post(struct dnet_node *n, char *addr, char *id, int length __unused)
{
	void *data;
	unsigned long data_size, size;
	char *p;
	long err;

	p = getenv("CONTENT_LENGTH");
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
		err = FCGI_fread(p, size, 1, FCGI_stdin);
		if (err < 0 && errno != EAGAIN) {
			fprintf(dnet_fcgi_log, "%s: failed to read %lu bytes, total of %lu: %s [%d].\n",
					addr, size, data_size, strerror(errno), errno);
			goto err_out_free;
		}

		if (FCGI_feof(FCGI_stdin)) {
			fprintf(dnet_fcgi_log, "%s: end of stdin, %lu/%lu, aborting.\n",
					addr, size, data_size);
			goto err_out_free;
		}

		if (err == 0) {
			fprintf(dnet_fcgi_log, "%s: short read, %lu/%lu, aborting.\n",
					addr, size, data_size);
			goto err_out_free;
		}

		p += err * size;
		size -= err * size;
	}

	err = dnet_fcgi_upload(n, addr, id, data, data_size);
	if (err)
		goto err_out_free;

	free(data);

	return 0;

err_out_free:
	free(data);
err_out_exit:
	return -EINVAL;
}

int main()
{
	char *p, *addr, *reason, *method;
	char *id_pattern, *id_delimiter;
	int length, id_pattern_length, err, post_allowed;
	char *id, *end;
	struct dnet_config cfg;
	struct dnet_node *n;

	dnet_fcgi_status_pattern = getenv("FCGI_DNET_SUCCESS_STATUS_PATTERN");
	if (!dnet_fcgi_status_pattern)
		dnet_fcgi_status_pattern = FCGI_DNET_SUCCESS_STATUS_PATTERN;

	dnet_fcgi_root_pattern = getenv("FCGI_DNET_ROOT_PATTERN");
	if (!dnet_fcgi_root_pattern)
		dnet_fcgi_root_pattern = FCGI_DNET_ROOT_PATTERN;

	p = getenv("FCGI_DNET_MAX_REQUEST_SIZE");
	if (p)
		dnet_fcgi_max_request_size = strtoul(p, NULL, 0);

	if (!dnet_fcgi_max_request_size)
		dnet_fcgi_max_request_size = DNET_FCGI_MAX_REQUEST_SIZE;

	p = getenv("FCGI_DNET_LOG");
	if (!p)
		p = FCGI_DNET_LOG;

	dnet_fcgi_log = fopen(p, "a");
	if (!dnet_fcgi_log) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s' log file.\n", p);
		goto err_out_exit;
	}

	p = getenv("FCGI_DNET_BASE_PORT");
	if (!p) {
		err = -ENOENT;
		fprintf(dnet_fcgi_log, "No FCGI_DNET_BASE_PORT provided, I will not be able to determine proper directory to fetch objects.\n");
		goto err_out_close;
	}
	dnet_fcgi_base_port = atoi(p);

	err = dnet_fcgi_fill_config(&cfg);
	if (err) {
		fprintf(dnet_fcgi_log, "Failed to parse config.\n");
		goto err_out_close;
	}

	n = dnet_node_create(&cfg);
	if (!n)
		goto err_out_close;

	err = dnet_fcgi_add_remote_addr(n, &cfg);
	if (err)
		goto err_out_free;

	err = dnet_fcgi_add_transform(n);
	if (err)
		goto err_out_free;

	post_allowed = 0;
	p = getenv("FCGI_DNET_POST_ALLOWED");
	if (p)
		post_allowed = atoi(p);

	fprintf(dnet_fcgi_log, "Started on %s, POST is %s.\n", getenv("SERVER_ADDR"), (post_allowed) ? "allowed" : "not allowed");
	fflush(dnet_fcgi_log);

	id_pattern = getenv("FCGI_DNET_ID_PATTERN");
	id_delimiter = getenv("FCGI_DNET_ID_DELIMITER");

	if (!id_pattern)
		id_pattern = FCGI_DNET_ID_PATTERN;
	if (!id_delimiter)
		id_delimiter = FCGI_DNET_ID_DELIMITER;

	id_pattern_length = strlen(id_pattern);

	while (FCGI_Accept() >= 0) {
		addr = getenv("REMOTE_ADDR");
		if (!addr)
			continue;

		method = getenv("REQUEST_METHOD");

		err = -EINVAL;
		p = getenv("QUERY_STRING");
		if (!p) {
			reason = "no query string";
			goto err_continue;
		}

		fprintf(dnet_fcgi_log, "Connect from: %s, method: %s, query: %s.\n", addr, method, p);

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
			end = p + strlen(p);

		length = end - id;

		fprintf(dnet_fcgi_log, "%s: id: '%s' [%d]\n", addr, id, length);

		if (!strncmp(method, "POST", 4)) {
			if (!post_allowed) {
				err = -EACCES;
				fprintf(dnet_fcgi_log, "%s: POST is not allowed for object '%s'.\n", addr, id);
				reason = "POST is not allowed";
				goto err_continue;
			}

			err = dnet_fcgi_handle_post(n, addr, id, length);
			if (err) {
				fprintf(dnet_fcgi_log, "%s: Failed to handle POST for object '%s': %d.\n", addr, id, err);
				reason = "failed to handle POST";
				goto err_continue;
			}
		} else {
			err = dnet_fcgi_lookup(n, id, length);
			if (err) {
				err = -errno;
				fprintf(dnet_fcgi_log, "%s: Failed to lookup object '%s': %d.\n", addr, id, err);
				reason = "failed to lookup object";
				goto err_continue;
			}
			fflush(dnet_fcgi_log);
		}

		FCGI_Finish();
		continue;

err_continue:
		FCGI_printf("Status: 417 Expectation Failed: %s\r\n\r\n", reason);
		FCGI_Finish();
		fprintf(dnet_fcgi_log, "%s: bad request: %s: %s [%d]\n", addr, reason, strerror(err), err);
		fflush(dnet_fcgi_log);
	}

	dnet_node_destroy(n);
	fflush(dnet_fcgi_log);
	fclose(dnet_fcgi_log);

	return 0;

err_out_free:
	dnet_node_destroy(n);
err_out_close:
	fflush(dnet_fcgi_log);
	fclose(dnet_fcgi_log);
err_out_exit:
	return err;
}
