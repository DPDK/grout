// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <string.h>

int br_infra_port_add(
	struct br_client *c,
	const char *name,
	const char *devargs,
	struct br_infra_port *port
) {
	struct br_infra_port_add_resp resp;
	struct br_infra_port_add_req req;

	if (port == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	strlcpy(req.name, name, sizeof(req.name));
	strlcpy(req.devargs, devargs, sizeof(req.devargs));

	if (send_recv(c, BR_INFRA_PORT_ADD, sizeof(req), &req, sizeof(resp), &resp) < 0)
		return -1;

	memcpy(port, &resp.port, sizeof(*port));

	return 0;
}

int br_infra_port_del(struct br_client *c, const char *name) {
	struct br_infra_port_del_req req;

	memset(&req, 0, sizeof(req));
	strlcpy(req.name, name, sizeof(req.name));

	return send_recv(c, BR_INFRA_PORT_DEL, sizeof(req), &req, 0, NULL);
}

int br_infra_port_get(struct br_client *c, const char *name, struct br_infra_port *port) {
	struct br_infra_port_get_resp resp;
	struct br_infra_port_get_req req;

	if (port == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	strlcpy(req.name, name, sizeof(req.name));

	if (send_recv(c, BR_INFRA_PORT_GET, sizeof(req), &req, sizeof(resp), &resp) < 0)
		return -1;

	memcpy(port, &resp.port, sizeof(*port));

	return 0;
}

int br_infra_port_list(
	struct br_client *c,
	size_t max_ports,
	struct br_infra_port *ports,
	size_t *n_ports
) {
	struct br_infra_port_list_resp resp;

	if (ports == NULL) {
		errno = EINVAL;
		return -1;
	}

	memset(&resp, 0, sizeof(resp));

	if (send_recv(c, BR_INFRA_PORT_LIST, 0, NULL, sizeof(resp), &resp) < 0)
		return -1;

	if (resp.n_ports > max_ports) {
		errno = ENOBUFS;
		return -1;
	}
	*n_ports = resp.n_ports;
	memcpy(ports, &resp.ports, resp.n_ports * sizeof(struct br_infra_port));

	return 0;
}
