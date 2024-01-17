// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#include "br_ip.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_ip_msg.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int br_ip_route4_add(
	const struct br_client *c,
	const struct ip4_net *dest,
	ip4_addr_t nh,
	bool exist_ok
) {
	struct br_ip_route4_add_req req;

	if (dest == NULL) {
		errno = EINVAL;
		return -1;
	}
	req.dest.addr = dest->addr;
	req.dest.prefixlen = dest->prefixlen;
	req.nh = nh;
	req.exist_ok = exist_ok;

	return send_recv(c, BR_IP_ROUTE4_ADD, sizeof(req), &req, NULL);
}

int br_ip_route4_del(const struct br_client *c, const struct ip4_net *dest, bool missing_ok) {
	struct br_ip_route4_del_req req;

	if (dest == NULL) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.dest, dest, sizeof(req.dest));
	req.missing_ok = missing_ok;

	return send_recv(c, BR_IP_ROUTE4_DEL, sizeof(req), &req, NULL);
}

int br_ip_route4_list(const struct br_client *c, size_t *n_routes, struct br_ip_route4 **routes) {
	struct br_ip_route4_list_resp *resp = NULL;
	int ret = -1;

	if (n_routes == NULL || routes == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_IP_ROUTE4_LIST, 0, NULL, (void **)&resp) < 0)
		goto out;

	*n_routes = resp->n_routes;
	*routes = calloc(resp->n_routes, sizeof(struct br_ip_route4));
	if (*routes == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*routes, &resp->routes, resp->n_routes * sizeof(struct br_ip_route4));

	ret = 0;
out:
	free(resp);
	return ret;
}
