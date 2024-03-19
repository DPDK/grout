// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "port_config.h"
#include "worker.h"

#include <br_api.h>
#include <br_control.h>
#include <br_infra_msg.h>
#include <br_infra_types.h>
#include <br_log.h>
#include <br_port.h>
#include <br_queue.h>
#include <br_worker.h>

#include <rte_build_config.h>
#include <rte_common.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

struct ports ports;

#define ETHER_FRAME_GAP 20

uint32_t port_get_rxq_buffer_us(uint16_t port_id, uint16_t rxq_id) {
	uint32_t frame_size, pkts_per_us;
	struct rte_eth_rxq_info qinfo;
	struct rte_eth_link link;
	int ret;

	if ((ret = rte_eth_link_get_nowait(port_id, &link)) < 0)
		return 0;
	switch (link.link_speed) {
	case RTE_ETH_SPEED_NUM_NONE:
	case RTE_ETH_SPEED_NUM_UNKNOWN:
		return 0;
	}

	if (rte_eth_rx_queue_info_get(port_id, rxq_id, &qinfo) < 0)
		return 0;

	// minimum ethernet frame size on the wire
	frame_size = (RTE_ETHER_MIN_LEN + ETHER_FRAME_GAP) * 8;

	// reported speed by driver is in megabit/s and we need a result in micro seconds.
	// we can use link_speed without any conversion: megabit/s is equivalent to bit/us
	pkts_per_us = link.link_speed / frame_size;
	if (pkts_per_us == 0)
		return 0;

	return qinfo.nb_desc / pkts_per_us;
}

static int fill_port_info(struct port *e, struct br_infra_port *port) {
	struct rte_eth_dev_info info;
	struct rte_ether_addr mac;
	int ret;

	memset(port, 0, sizeof(*port));
	port->index = e->port_id;

	if ((ret = rte_eth_dev_info_get(e->port_id, &info)) < 0)
		return ret;
	if ((ret = rte_eth_macaddr_get(e->port_id, &mac)) < 0)
		return ret;

	port->n_rxq = info.nb_rx_queues;
	port->n_txq = info.nb_tx_queues;
	port->rxq_size = e->rxq_size;
	port->txq_size = e->txq_size;

	memccpy(port->device, rte_dev_name(info.device), 0, sizeof(port->device));
	memcpy(port->mac.bytes, mac.addr_bytes, sizeof(port->mac.bytes));

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

	port = calloc(1, sizeof(*port));
	if (port == NULL) {
		port_destroy(port_id, NULL);
		return api_out(ENOMEM, 0);
	}

	port->port_id = port_id;
	LIST_INSERT_HEAD(&ports, port, next);

	if ((ret = port_reconfig(port)) < 0) {
		port_destroy(port_id, port);
		return api_out(-ret, 0);
	}
	if ((ret = port_plug(port)) < 0) {
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
	size_t len;
	int ret;

	(void)request;

	LIST_FOREACH (port, &ports, next)
		n_ports++;

	len = sizeof(*resp) + n_ports * sizeof(struct br_infra_port);
	if ((resp = malloc(len)) == NULL)
		return api_out(ENOMEM, 0);

	memset(resp, 0, len);

	n_ports = 0;
	LIST_FOREACH (port, &ports, next) {
		struct br_infra_port *p = &resp->ports[n_ports];
		if ((ret = fill_port_info(port, p)) < 0) {
			free(resp);
			return api_out(-ret, 0);
		}
		n_ports++;
	}

	resp->n_ports = n_ports;

	*response = resp;

	return api_out(0, len);
}

static struct api_out port_set(const void *request, void **response) {
	const struct br_infra_port_set_req *req = request;
	bool reconfig = false;
	struct port *port;

	int ret;

	(void)response;

	if (req->set_attrs == 0)
		return api_out(EINVAL, 0);

	if ((port = find_port(req->port_id)) == NULL)
		return api_out(ENODEV, 0);

	if ((ret = port_unplug(port)) < 0)
		return api_out(-ret, 0);

	if (req->set_attrs & BR_INFRA_PORT_N_RXQ) {
		port->n_rxq = req->n_rxq;
		reconfig = true;
	}
	if (req->set_attrs & BR_INFRA_PORT_Q_SIZE) {
		port->rxq_size = req->q_size;
		port->txq_size = req->q_size;
		reconfig = true;
	}
	if (reconfig && (ret = port_reconfig(port)) < 0)
		return api_out(-ret, 0);

	if ((ret = port_plug(port)) < 0)
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
	.name = "port",
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
