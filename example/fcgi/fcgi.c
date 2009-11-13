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

#define FCGI_DNET_ID_PATTERN		"id="
#define FCGI_DNET_ID_DELIMITER		"&"
#define FCGI_DNET_LOG			"/tmp/dnet_fcgi.log"
#define FCGI_DNET_LOCAL_ADDR		"0.0.0.0:1025:2"
#define FCGI_DNET_SUCCESS_STATUS_PATTERN	"Status: 301"
#define FCGI_DNET_ROOT_PATTERN		""

static FILE *dnet_fcgi_log;
static pthread_cond_t dnet_fcgi_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dnet_fcgi_wait_lock = PTHREAD_MUTEX_INITIALIZER;
static int dnet_fcgi_request_completed, dnet_fcgi_request_init_value = 11223344;
static char *dnet_fcgi_status_pattern, *dnet_fcgi_root_pattern;

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
			continue;
		}

		err = dnet_add_state(n, &cfg);
		if (err) {
			fprintf(dnet_fcgi_log, "Failed to add addr '%s': %d.\n", addr, err);
			continue;
		}

		added++;

		if (!p)
			break;

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

static void dnet_fcgi_wait(void)
{
	pthread_mutex_lock(&dnet_fcgi_wait_lock);
	while (dnet_fcgi_request_completed == dnet_fcgi_request_init_value)
		pthread_cond_wait(&dnet_fcgi_cond, &dnet_fcgi_wait_lock);
	pthread_mutex_unlock(&dnet_fcgi_wait_lock);
}

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

	if (cmd->status || !cmd->size) {
		err = cmd->status;
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
			FCGI_printf("%s\r\n", dnet_fcgi_status_pattern);
			FCGI_printf("Location: http://%s%s/%02x/%s\r\n",
					dnet_state_dump_addr_only(&a->addr),
					dnet_fcgi_root_pattern,
					cmd->id[0], dnet_dump_id_len(cmd->id, DNET_ID_SIZE));

			fprintf(dnet_fcgi_log, "%s -> http://%s%s/%02x/%s\n",
					dnet_fcgi_status_pattern,
					dnet_state_dump_addr_only(&a->addr),
					dnet_fcgi_root_pattern,
					cmd->id[0], dnet_dump_id_len(cmd->id, DNET_ID_SIZE));
			err = 0;
		}

		dnet_fcgi_wakeup(err);
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

		dnet_fcgi_wait();

		if (dnet_fcgi_request_completed < 0) {
			error = dnet_fcgi_request_completed;
			continue;
		}

		error = 0;
		break;
	}

	return error;
}

int main()
{
	char *p, *addr, *reason;
	char *id_pattern, *id_delimiter;
	int length, id_pattern_length, err;
	char *id, *end;
	struct dnet_config cfg;
	struct dnet_node *n;

	p = getenv("FCGI_DNET_LOG");
	if (!p)
		p = FCGI_DNET_LOG;

	dnet_fcgi_status_pattern = getenv("FCGI_DNET_SUCCESS_STATUS_PATTERN");
	if (!dnet_fcgi_status_pattern)
		dnet_fcgi_status_pattern = FCGI_DNET_SUCCESS_STATUS_PATTERN;

	dnet_fcgi_root_pattern = getenv("FCGI_DNET_ROOT_PATTERN");
	if (!dnet_fcgi_root_pattern)
		dnet_fcgi_root_pattern = FCGI_DNET_ROOT_PATTERN;

	dnet_fcgi_log = fopen(p, "a");
	if (!dnet_fcgi_log) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s' log file.\n", p);
		goto err_out_exit;
	}

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

	fprintf(dnet_fcgi_log, "Started on %s!\n", getenv("SERVER_ADDR"));
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

		fprintf(dnet_fcgi_log, "Connect from: %s\n", addr);

		FCGI_printf("Content-type: text/html\r\n");

		p = getenv("QUERY_STRING");
		if (!p) {
			reason = "no query string";
			goto err_continue;
		}

		fprintf(dnet_fcgi_log, "%s: query: %s\n", addr, p);

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

		err = dnet_fcgi_lookup(n, id, length);
		if (err) {
			fprintf(dnet_fcgi_log, "%s: Failed to lookup object '%s': %d.\n", addr, id, err);
			reason = "failed to lookup object";
			goto err_continue;
		}

		FCGI_printf("\r\n\r\n");
		fflush(dnet_fcgi_log);
		continue;

err_continue:
		FCGI_printf("Status: 417 Expectation Failed: %s\r\n\r\n", reason);
		fprintf(dnet_fcgi_log, "%s: bad request: %s\n", addr, reason);
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
