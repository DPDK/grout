// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_ip4.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_ip4_msg.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int br_ip4_route_add(
	const struct br_client *c,
	const struct ip4_net *dest,
	ip4_addr_t nh,
	bool exist_ok
) {
	struct br_ip4_route_add_req req;

	if (dest == NULL) {
		errno = EINVAL;
		return -1;
	}
	req.dest.ip = dest->ip;
	req.dest.prefixlen = dest->prefixlen;
	req.nh = nh;
	req.exist_ok = exist_ok;

	return send_recv(c, BR_IP4_ROUTE_ADD, sizeof(req), &req, NULL);
}

int br_ip4_route_del(const struct br_client *c, const struct ip4_net *dest, bool missing_ok) {
	struct br_ip4_route_del_req req;

	if (dest == NULL) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.dest, dest, sizeof(req.dest));
	req.missing_ok = missing_ok;

	return send_recv(c, BR_IP4_ROUTE_DEL, sizeof(req), &req, NULL);
}

int br_ip4_route_get(const struct br_client *c, ip4_addr_t dest, struct br_ip4_nh *nh) {
	const struct br_ip4_route_get_resp *resp;
	struct br_ip4_route_get_req req;
	void *resp_ptr = NULL;
	int ret = -1;

	if (nh == NULL) {
		errno = EINVAL;
		goto out;
	}

	req.dest = dest;
	if ((ret = send_recv(c, BR_IP4_ROUTE_GET, sizeof(req), &req, &resp_ptr)) < 0)
		goto out;

	resp = resp_ptr;
	memcpy(nh, &resp->nh, sizeof(*nh));
	ret = 0;
out:
	free(resp_ptr);
	return ret;
}

int br_ip4_route_list(const struct br_client *c, size_t *n_routes, struct br_ip4_route **routes) {
	const struct br_ip4_route_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (n_routes == NULL || routes == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_IP4_ROUTE_LIST, 0, NULL, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	*n_routes = resp->n_routes;
	*routes = calloc(resp->n_routes, sizeof(struct br_ip4_route));
	if (*routes == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*routes, &resp->routes, resp->n_routes * sizeof(struct br_ip4_route));

	ret = 0;
out:
	free(resp_ptr);
	return ret;
}
