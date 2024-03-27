// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

int br_infra_port_add(const struct br_client *c, const char *devargs, uint16_t *port_id) {
	struct br_infra_port_add_resp *resp = NULL;
	struct br_infra_port_add_req req;
	int ret = -1;

	memset(&req, 0, sizeof(req));
	memccpy(req.devargs, devargs, 0, sizeof(req.devargs));

	if (send_recv(c, BR_INFRA_PORT_ADD, sizeof(req), &req, (void *)&resp) < 0)
		goto out;

	if (port_id != NULL)
		*port_id = resp->port_id;

	ret = 0;
out:
	free(resp);
	return ret;
}

int br_infra_port_del(const struct br_client *c, uint16_t port_id) {
	struct br_infra_port_del_req req = {port_id};

	return send_recv(c, BR_INFRA_PORT_DEL, sizeof(req), &req, NULL);
}

int br_infra_port_get(const struct br_client *c, uint16_t port_id, struct br_infra_port *port) {
	struct br_infra_port_get_req req = {port_id};
	struct br_infra_port_get_resp *resp = NULL;
	int ret = -1;

	if (port == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_INFRA_PORT_GET, sizeof(req), &req, (void *)&resp) < 0)
		goto out;

	memcpy(port, &resp->port, sizeof(*port));

	ret = 0;
out:
	free(resp);
	return ret;
}

int br_infra_port_list(const struct br_client *c, size_t *n_ports, struct br_infra_port **ports) {
	struct br_infra_port_list_resp *resp = NULL;
	int ret = -1;

	if (n_ports == NULL || ports == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_INFRA_PORT_LIST, 0, NULL, (void *)&resp) < 0)
		goto out;

	*n_ports = resp->n_ports;
	*ports = calloc(resp->n_ports, sizeof(struct br_infra_port));
	if (*ports == NULL) {
		errno = ENOMEM;
		goto out;
	}
	memcpy(*ports, &resp->ports, resp->n_ports * sizeof(struct br_infra_port));

	ret = 0;
out:
	free(resp);
	return ret;
}

int br_infra_port_set(
	const struct br_client *c,
	uint16_t port_id,
	uint16_t n_rxq,
	uint16_t q_size
) {
	struct br_infra_port_set_req req = {
		.port_id = port_id,
	};
	if (n_rxq > 0) {
		req.n_rxq = n_rxq;
		req.set_attrs |= BR_INFRA_PORT_N_RXQ;
	}
	if (q_size > 0) {
		req.q_size = q_size;
		req.set_attrs |= BR_INFRA_PORT_Q_SIZE;
	}
	return send_recv(c, BR_INFRA_PORT_SET, sizeof(req), &req, NULL);
}
