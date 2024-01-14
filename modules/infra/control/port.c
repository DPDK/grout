// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "port_config.h"
#include "worker.h"

#include <br_api.h>
#include <br_control.h>
#include <br_infra_msg.h>
#include <br_infra_types.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

struct ports ports;

uint16_t port_get_burst_size(uint16_t port_id) {
	struct port *port;

	LIST_FOREACH (port, &ports, next) {
		if (port->port_id == port_id)
			return port->burst;
	}
	return BR_INFRA_PORT_BURST_DEFAULT;
}

static int fill_port_info(struct port *e, struct br_infra_port *port) {
	struct rte_eth_dev_info info;
	int ret;

	memset(port, 0, sizeof(*port));
	port->index = e->port_id;

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;

	port->n_rxq = info.nb_rx_queues;
	port->n_txq = info.nb_tx_queues;
	port->burst = e->burst;

	memccpy(port->device, rte_dev_name(info.device), 0, sizeof(port->device));

	return 0;
}

static struct api_out port_add(const void *request, void **response) {
	const struct br_infra_port_add_req *req = request;
	struct br_infra_port_add_resp *resp;
	uint16_t port_id = RTE_MAX_ETHPORTS;
	struct rte_dev_iterator iterator;
	struct port *port;
	int ret;

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		return api_out(EEXIST, 0);
	}

	if ((ret = rte_dev_probe(req->devargs)) < 0)
		return api_out(-ret, 0);

	RTE_ETH_FOREACH_MATCHING_DEV(port_id, req->devargs, &iterator) {
		rte_eth_iterator_cleanup(&iterator);
		break;
	}
	if (!rte_eth_dev_is_valid_port(port_id))
		return api_out(ENOENT, 0);

	port = rte_zmalloc("port", sizeof(*port), 0);
	if (port == NULL) {
		port_destroy(port_id, NULL);
		return api_out(ENOMEM, 0);
	}

	port->port_id = port_id;
	port->burst = BR_INFRA_PORT_BURST_DEFAULT;
	LIST_INSERT_HEAD(&ports, port, next);

	if ((ret = port_reconfig(port, 1)) < 0) {
		port_destroy(port_id, port);
		return api_out(-ret, 0);
	}
	if ((ret = port_plug(port, true)) < 0) {
		port_destroy(port_id, port);
		return api_out(-ret, 0);
	}

	if ((resp = malloc(sizeof(*resp))) == NULL) {
		port_destroy(port_id, port);
		return api_out(ENOMEM, 0);
	}

	resp->port_id = port_id;
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct port *find_port(uint16_t port_id) {
	struct port *port;
	LIST_FOREACH (port, &ports, next) {
		if (port->port_id == port_id)
			return port;
	}
	return NULL;
}

static struct api_out port_del(const void *request, void **response) {
	const struct br_infra_port_del_req *req = request;
	struct port *port;
	int ret;

	(void)response;

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	ret = port_destroy(port->port_id, port);

	return api_out(-ret, 0);
}

static struct api_out port_get(const void *request, void **response) {
	const struct br_infra_port_get_req *req = request;
	struct br_infra_port_get_resp *resp = NULL;
	struct port *port;
	int ret;

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	if ((resp = malloc(sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	if ((ret = fill_port_info(port, &resp->port)) < 0) {
		free(resp);
		return api_out(-ret, 0);
	}
	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out port_list(const void *request, void **response) {
	struct br_infra_port_list_resp *resp = NULL;
	uint16_t n_ports = 0;
	struct port *port;
	int ret;

	(void)request;

	LIST_FOREACH (port, &ports, next)
		n_ports++;

	if ((resp = malloc(sizeof(*resp) + n_ports * (sizeof(*port)))) == NULL)
		return api_out(ENOMEM, 0);

	resp->n_ports = n_ports;

	LIST_FOREACH (port, &ports, next) {
		struct br_infra_port *p = &resp->ports[resp->n_ports];
		if ((ret = fill_port_info(port, p)) < 0) {
			free(resp);
			return api_out(-ret, 0);
		}
		resp->n_ports++;
	}

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out port_set(const void *request, void **response) {
	const struct br_infra_port_set_req *req = request;
	struct port *port;

	int ret;

	(void)response;

	if ((req->set_attrs & (BR_INFRA_PORT_N_RXQ | BR_INFRA_PORT_BURST)) == 0)
		return api_out(EINVAL, 0);

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	if ((ret = port_unplug(port, true)) < 0)
		return api_out(-ret, 0);

	if (req->set_attrs & BR_INFRA_PORT_N_RXQ) {
		if ((ret = port_reconfig(port, req->n_rxq)) < 0)
			return api_out(-ret, 0);
	}

	if (req->set_attrs & BR_INFRA_PORT_BURST)
		port->burst = req->burst;

	if ((ret = port_plug(port, true)) < 0)
		return api_out(-ret, 0);

	return api_out(0, 0);
}

static struct br_api_handler port_add_handler = {
	.name = "port add",
	.request_type = BR_INFRA_PORT_ADD,
	.callback = port_add,
};
static struct br_api_handler port_del_handler = {
	.name = "port del",
	.request_type = BR_INFRA_PORT_DEL,
	.callback = port_del,
};
static struct br_api_handler port_get_handler = {
	.name = "port get",
	.request_type = BR_INFRA_PORT_GET,
	.callback = port_get,
};
static struct br_api_handler port_list_handler = {
	.name = "port list",
	.request_type = BR_INFRA_PORT_LIST,
	.callback = port_list,
};
static struct br_api_handler port_set_handler = {
	.name = "port set",
	.request_type = BR_INFRA_PORT_SET,
	.callback = port_set,
};

static void port_fini(void) {
	struct port *port, *tmp;

	LIST_FOREACH_SAFE (port, &ports, next, tmp)
		port_destroy(port->port_id, port);

	LIST_INIT(&ports);
}

static struct br_module port_module = {
	.fini = port_fini,
	.fini_prio = 1000,
};

RTE_INIT(control_infra_init) {
	br_register_api_handler(&port_add_handler);
	br_register_api_handler(&port_del_handler);
	br_register_api_handler(&port_get_handler);
	br_register_api_handler(&port_list_handler);
	br_register_api_handler(&port_set_handler);
	br_register_module(&port_module);
}
