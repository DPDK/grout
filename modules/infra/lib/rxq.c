// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int br_infra_rxq_list(const struct br_client *c, size_t *n_rxqs, struct br_infra_rxq **rxqs) {
	const struct br_infra_rxq_list_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (n_rxqs == NULL || rxqs == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_INFRA_RXQ_LIST, 0, NULL, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	*n_rxqs = resp->n_rxqs;
	*rxqs = calloc(resp->n_rxqs, sizeof(struct br_infra_rxq));
	if (*rxqs == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*rxqs, &resp->rxqs, resp->n_rxqs * sizeof(struct br_infra_rxq));

	ret = 0;
out:
	free(resp_ptr);
	return ret;
}

int br_infra_rxq_set(
	const struct br_client *c,
	uint16_t port_id,
	uint16_t rxq_id,
	uint16_t cpu_id
) {
	struct br_infra_rxq_set_req req = {
		.port_id = port_id,
		.rxq_id = rxq_id,
		.cpu_id = cpu_id,
	};
	return send_recv(c, BR_INFRA_RXQ_SET, sizeof(req), &req, NULL);
}
