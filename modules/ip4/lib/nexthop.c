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

int br_ip4_nh_add(const struct br_client *c, const struct br_ip4_nh *nh, bool exist_ok) {
	struct br_ip4_nh_add_req req;

	if (nh == NULL) {
		errno = EINVAL;
		return -1;
	}
	memcpy(&req.nh, nh, sizeof(req.nh));
	req.exist_ok = exist_ok;

	return send_recv(c, BR_IP4_NH_ADD, sizeof(req), &req, NULL);
}

int br_ip4_nh_del(const struct br_client *c, ip4_addr_t host, bool missing_ok) {
	struct br_ip4_nh_del_req req = {
		.host = host,
		.missing_ok = missing_ok,
	};
	return send_recv(c, BR_IP4_NH_DEL, sizeof(req), &req, NULL);
}

int br_ip4_nh_list(const struct br_client *c, size_t *n_nhs, struct br_ip4_nh **nhs) {
	const struct br_ip4_nh_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (n_nhs == NULL || nhs == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_IP4_NH_LIST, 0, NULL, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	*n_nhs = resp->n_nhs;
	*nhs = calloc(resp->n_nhs, sizeof(struct br_ip4_nh));
	if (*nhs == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*nhs, &resp->nhs, resp->n_nhs * sizeof(struct br_ip4_nh));

	ret = 0;
out:
	free(resp_ptr);
	return ret;
}
