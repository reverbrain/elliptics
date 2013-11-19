/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/interface.h"

static int dnet_discover_loop = 1;
static int dnet_discover_ttl = 3;

static int dnet_discovery_add_v4(struct dnet_node *n, struct dnet_addr *addr, int s)
{
	int err;
	struct group_req command;

	err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &dnet_discover_loop, sizeof(dnet_discover_loop));
	if (err < 0) {
		err = -errno;
    		dnet_log_err(n, "unable to set loopback option");
		goto err_out_exit;
  	}

	err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &dnet_discover_ttl, sizeof(dnet_discover_ttl));
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "unable to set %d hop limit", dnet_discover_ttl);
		goto err_out_exit;
	}

	memset(&command, 0, sizeof(struct group_req));
	memcpy(&command.gr_group, addr->addr, addr->addr_len);

	err = setsockopt(s, IPPROTO_IP, MCAST_JOIN_GROUP, &command, sizeof(command));
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "can not add multicast membership: %s", dnet_server_convert_dnet_addr(addr));
		goto err_out_exit;
	}

err_out_exit:
	return err;
}

static int dnet_discovery_add_v6(struct dnet_node *n, struct dnet_addr *addr, int s)
{
	int err;
	struct group_req command;

	err = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &dnet_discover_loop, sizeof(dnet_discover_loop));
	if (err < 0) {
		err = -errno;
    		dnet_log_err(n, "unable to set loopback option");
		goto err_out_exit;
  	}

	err = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &dnet_discover_ttl, sizeof(dnet_discover_ttl));
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "unable to set %d hop limit", dnet_discover_ttl);
		goto err_out_exit;
	}

	memset(&command, 0, sizeof(struct group_req));
	memcpy(&command.gr_group, addr->addr, addr->addr_len);

	err = setsockopt(s, IPPROTO_IPV6, MCAST_JOIN_GROUP, &command, sizeof(command));
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "can not add multicast membership: %s", dnet_server_convert_dnet_addr(addr));
		goto err_out_exit;
	}


err_out_exit:
	return err;
}

int dnet_discovery_add(struct dnet_node *n, char *remote_addr, int remote_port, int remote_family)
{
	struct dnet_addr addr;
	int proto, sock_type;
	int err = -EEXIST;
	int s;

	if (n->autodiscovery_socket != -1)
		goto err_out_exit;

	memset(&addr, 0, sizeof(struct dnet_addr));

	sock_type = SOCK_DGRAM;
	proto = IPPROTO_IP;
	if (remote_family == AF_INET6)
		proto = IPPROTO_IPV6;
	addr.addr_len = sizeof(addr.addr);
	addr.family = remote_family;

	err = dnet_fill_addr(&addr, remote_addr, remote_port, sock_type, proto);
	if (err) {
		dnet_log(n, DNET_LOG_ERROR, "Failed to get address info for %s:%d, family: %d, err: %d: %s.\n",
				remote_addr, remote_port, remote_family, err, strerror(-err));
		goto err_out_exit;
	}

	s = socket(remote_family, sock_type, 0);
	if (s < 0) {
		err = -errno;
		dnet_log_err(n, "failed to create multicast socket");
		goto err_out_exit;
	}

	err = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &err, 4);

	err = bind(s, (struct sockaddr *)addr.addr, addr.addr_len);
	if (err) {
		err = -errno;
		dnet_log_err(n, "Failed to bind to %s",
				dnet_server_convert_dnet_addr(&addr));
		goto err_out_close;
	}

	if (remote_family == AF_INET6)
		err = dnet_discovery_add_v6(n, &addr, s);
	else
		err = dnet_discovery_add_v4(n, &addr, s);

	if (err)
		goto err_out_close;

	n->autodiscovery_socket = s;
	n->autodiscovery_addr = addr;
	return 0;

err_out_close:
	close(s);
err_out_exit:
	return err;
}

static int dnet_discovery_send(struct dnet_node *n)
{
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_auth) + sizeof(struct dnet_addr)];
	struct dnet_cmd *cmd;
	struct dnet_addr *addr;
	struct dnet_auth *auth;
	int err;

	memset(buf, 0, sizeof(buf));

	cmd = (struct dnet_cmd *)buf;
	addr = (struct dnet_addr *)(cmd + 1);
	auth = (struct dnet_auth *)(addr + 1);

	cmd->id = n->id;
	cmd->size = sizeof(struct dnet_addr) + sizeof(struct dnet_auth);
	dnet_convert_cmd(cmd);

	*addr = n->st->addr;
	dnet_convert_addr(addr);

	memcpy(auth->cookie, n->cookie, DNET_AUTH_COOKIE_SIZE);
	dnet_convert_auth(auth);

	err = sendto(n->autodiscovery_socket, buf, sizeof(buf), 0, (void *)&n->autodiscovery_addr, n->autodiscovery_addr.addr_len);
	if (err < 0) {
		err = -errno;
		dnet_log_err(n, "autodiscovery sent: %s - %.*s", dnet_server_convert_dnet_addr(addr),
			(int)sizeof(auth->cookie), auth->cookie);
	} else {
		dnet_log(n, DNET_LOG_NOTICE, "autodiscovery sent: %s - %.*s\n", dnet_server_convert_dnet_addr(addr),
			(int)sizeof(auth->cookie), auth->cookie);
	}

	return err;
}

static int dnet_discovery_add_state(struct dnet_node *n, struct dnet_addr *addr)
{
	char addr_str[128];
	int port;

	dnet_server_convert_addr_raw((struct sockaddr *)addr->addr, addr->addr_len, addr_str, sizeof(addr_str));
	port = dnet_server_convert_port((struct sockaddr *)addr->addr, addr->addr_len);

	return dnet_add_state(n, addr_str, port, addr->family, 0);
}

static int dnet_discovery_recv(struct dnet_node *n)
{
	char buf[sizeof(struct dnet_cmd) + sizeof(struct dnet_auth) + sizeof(struct dnet_addr)];
	struct dnet_cmd *cmd;
	struct dnet_addr *addr;
	struct dnet_auth *auth;
	int err;
	struct dnet_addr remote;
	socklen_t len = n->autodiscovery_addr.addr_len;

	remote = n->autodiscovery_addr;

	cmd = (struct dnet_cmd *)buf;
	addr = (struct dnet_addr *)(cmd + 1);
	auth = (struct dnet_auth *)(addr + 1);

	while (1) {
		struct pollfd pfd;

		pfd.fd = n->autodiscovery_socket;
		pfd.events = POLLIN;
		pfd.revents = 0;

		err = poll(&pfd, 1, 100);
		if (err < 0) {
			err = -errno;
			dnet_log(n, DNET_LOG_ERROR, "autodiscovery-recv: poll: %s [%d]\n", strerror(-err), err);
		}

		if (err == 0) {
			dnet_log(n, DNET_LOG_DEBUG, "autodiscovery-recv: poll: no data\n");
			return -EAGAIN;
		}

		err = recvfrom(n->autodiscovery_socket, buf, sizeof(buf), 0, (void *)&remote, &len);
		if (err == -1) {
			err = -errno;
			dnet_log(n, DNET_LOG_ERROR, "audodiscovery recv: %d, want: %zd: %s [%d]\n", err, sizeof(buf), strerror(-err), err);
		}

		if (err != sizeof(buf))
			return -EAGAIN;

		dnet_convert_cmd(cmd);
		dnet_convert_addr(addr);
		dnet_convert_auth(auth);

		dnet_log(n, DNET_LOG_NOTICE, "autodiscovery recv: %s - %.*s\n", dnet_server_convert_dnet_addr(addr),
				(int)sizeof(auth->cookie), auth->cookie);

		if (!memcmp(n->cookie, auth->cookie, DNET_AUTH_COOKIE_SIZE)) {
			dnet_discovery_add_state(n, addr);
		}
	}

	return 0;
}

int dnet_discovery(struct dnet_node *n)
{
	int err;

	if (n->autodiscovery_socket == -1)
		return -ENOTSUP;

	err = dnet_discovery_recv(n);

	if (n->flags & DNET_CFG_JOIN_NETWORK)
		err = dnet_discovery_send(n);

	return err;
}
