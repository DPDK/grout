// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_ip4.h"
#include "br_ip4_types.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_ip4_msg.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int br_ip4_addr_add(const struct br_client *c, const struct br_ip4_addr *addr, bool exist_ok) {
	struct br_ip4_addr_add_req req = {.exist_ok = exist_ok};

	if (addr == NULL) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.addr, addr, sizeof(req.addr));

	return send_recv(c, BR_IP4_ADDR_ADD, sizeof(req), &req, NULL);
}

int br_ip4_addr_del(const struct br_client *c, const struct br_ip4_addr *addr, bool missing_ok) {
	struct br_ip4_addr_del_req req = {.missing_ok = missing_ok};

	if (addr == NULL) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.addr, addr, sizeof(req.addr));

	return send_recv(c, BR_IP4_ADDR_DEL, sizeof(req), &req, NULL);
}

int br_ip4_addr_list(const struct br_client *c, size_t *n_addrs, struct br_ip4_addr **addrs) {
	const struct br_ip4_addr_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (n_addrs == NULL || addrs == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_IP4_ADDR_LIST, 0, NULL, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	*n_addrs = resp->n_addrs;
	*addrs = calloc(resp->n_addrs, sizeof(struct br_ip4_addr));
	if (*addrs == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*addrs, &resp->addrs, resp->n_addrs * sizeof(struct br_ip4_addr));

	ret = 0;
out:
	free(resp_ptr);
	return ret;
}
