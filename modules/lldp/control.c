// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_lldp.h"
#include "lldp_priv.h"

#include <gr_api.h>
#include <gr_control.h>
#include <gr_graph.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_port.h>
#include <gr_worker.h>

#include <event2/event.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_version.h>

static struct rte_ether_addr lldp_dst0 = {
	.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00},
};
static struct rte_ether_addr lldp_dst1 = {
	.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
};
static struct rte_ether_addr lldp_dst2 = {
	.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
};

struct gr_lldp_conf_iface_data lldp_iface_ctx[RTE_MAX_ETHPORTS];
struct gr_lldp_conf_common_data lldp_ctx;
static struct gr_lldp_conf_iface_data lldp_default_conf;

static struct event *lldp_output_timer;

static void lldp_output_cb(evutil_socket_t, short, void *) {
	const struct iface *iface = NULL;
	struct iface_info_port *port;

	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		port = (struct iface_info_port *)iface->info;
		if (lldp_iface_ctx[port->port_id].tx)
			lldp_output_emit(iface);
	}
}

static struct api_out lldp_set_global_conf(const void *request, void **response) {
	const struct gr_lldp_set_global_conf_req *req = request;
	(void)response;

	if (req->set_attrs & GR_LLDP_SET_NAME)
		strcpy(lldp_ctx.sys_name, req->sys_name);

	if (req->set_attrs & GR_LLDP_SET_DESC)
		strcpy(lldp_ctx.sys_descr, req->sys_descr);

	if (req->set_attrs & GR_LLDP_SET_TTL) {
		lldp_ctx.ttl = req->ttl;
		struct timeval tv = {.tv_sec = lldp_ctx.ttl};
		event_del(lldp_output_timer);
		if (event_add(lldp_output_timer, &tv) < 0) {
			return api_out(ENOSYS, 0);
		}
	}

	// On config update, send immediately a new LLDP frame
	event_active(lldp_output_timer, 0, 0);
	return api_out(0, 0);
}

static struct api_out lldp_set_iface_conf(const void *request, void **response) {
	struct gr_lldp_neigh *neighbors = lldp_get_neighbors();
	const struct gr_lldp_set_iface_conf_req *req = request;
	(void)response;

	if (req->set_attrs & GR_LLDP_SET_IFACE_UNIQUE) {
		struct iface_info_port *port;
		struct iface *iface;

		iface = iface_from_id(req->ifid);
		if (iface == NULL)
			return api_out(ENODEV, 0);

		if (iface->type_id != GR_IFACE_TYPE_PORT)
			return api_out(EINVAL, 0);

		port = (struct iface_info_port *)iface->info;
		if (req->set_attrs & GR_LLDP_SET_RX)
			lldp_iface_ctx[port->port_id].rx = req->rx;
		if (req->set_attrs & GR_LLDP_SET_TX)
			lldp_iface_ctx[port->port_id].tx = req->tx;
		if (lldp_iface_ctx[port->port_id].rx == 0)
			memset(&neighbors[port->port_id], 0, sizeof(neighbors[0]));

	} else if (req->set_attrs & GR_LLDP_SET_IFACE_ALL) {
		if (req->set_attrs & GR_LLDP_SET_RX) {
			if (req->rx == 0) {
				for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
					memset(neighbors, 0, sizeof(neighbors[0]) * RTE_MAX_ETHPORTS
					);
				}
			}
			for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
				lldp_iface_ctx[i].rx = req->rx;
			}
		}
		if (req->set_attrs & GR_LLDP_SET_TX) {
			for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
				lldp_iface_ctx[i].tx = req->tx;
			}
		}
	} else if (req->set_attrs & GR_LLDP_SET_IFACE_DEFAULT) {
		if (req->set_attrs & GR_LLDP_SET_RX)
			lldp_default_conf.rx = req->rx;
		if (req->set_attrs & GR_LLDP_SET_TX)
			lldp_default_conf.tx = req->tx;
	}

	// On config update, send immediately a new LLDP frame
	struct timeval tv = {.tv_sec = lldp_ctx.ttl};
	event_del(lldp_output_timer);
	if (event_add(lldp_output_timer, &tv) < 0)
		return api_out(ENOSYS, 0);

	event_active(lldp_output_timer, 0, 0);

	return api_out(0, 0);
}

static struct api_out lldp_show_config(const void *request, void **response) {
	struct gr_lldp_show_config_resp *resp = NULL;
	(void)request;

	if ((resp = calloc(1, sizeof(*resp))) == NULL)
		return api_out(ENOMEM, 0);

	memcpy(&resp->common, &lldp_ctx, sizeof(struct gr_lldp_conf_common_data));

	for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
		const struct iface *iface = port_get_iface(i);
		if (iface) {
			strcpy(resp->if_name[i], iface->name);
			resp->iface[i].rx = lldp_iface_ctx[i].rx;
			resp->iface[i].tx = lldp_iface_ctx[i].tx;
		}
	}

	*response = resp;

	return api_out(0, sizeof(*resp));
}

static struct api_out lldp_show_neighbors(const void *request, void **response) {
	struct gr_lldp_neigh *neighbors = lldp_get_neighbors();
	struct gr_lldp_show_neighbors_resp *resp = NULL;
	uint16_t n_neigh = 0;
	int sz = 0;
	(void)request;

	for (uint16_t i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (neighbors[i].last_seen != 0)
			n_neigh++;
	}
	sz = sizeof(*resp) + n_neigh * sizeof(resp->neighbors[0]);

	if ((resp = calloc(1, sz)) == NULL)
		return api_out(ENOMEM, 0);

	resp->now = clock();
	resp->n_neigh = n_neigh;

	for (uint16_t i = 0, n = 0; i < RTE_MAX_ETHPORTS && n < n_neigh; i++) {
		if (neighbors[i].last_seen != 0) {
			resp->neighbors[n].iface_id = neighbors[i].iface_id;
			resp->neighbors[n].last_seen = neighbors[i].last_seen;
			resp->neighbors[n].n_tlv_data = neighbors[i].n_tlv_data;

			memcpy(resp->neighbors[n].tlv_data,
			       neighbors[i].tlv_data,
			       neighbors[i].n_tlv_data);
			n++;
		}
	}
	*response = resp;

	return api_out(0, sz);
}

static void lldp_control_init(struct event_base *ev_base) {
	snprintf(lldp_ctx.sys_name, LLDP_STR_SIZE, "Grout");
	snprintf(
		lldp_ctx.sys_descr,
		LLDP_STR_SIZE,
		"Graph router version %s - dpdk %s",
		GROUT_VERSION,
		rte_version()
	);

	lldp_ctx.ttl = 60;

	lldp_default_conf.rx = 1;
	lldp_default_conf.tx = 1;

	lldp_output_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, lldp_output_cb, NULL);
	if (lldp_output_timer == NULL)
		ABORT("event_new() failed");

	struct timeval tv = {.tv_sec = lldp_ctx.ttl};
	if (event_add(lldp_output_timer, &tv) < 0)
		ABORT("event_add() failed");
}

static void lldp_control_fini(struct event_base *) {
	event_free(lldp_output_timer);
	lldp_output_timer = NULL;
}

static void lldp_iface_event(iface_event_t evt, struct iface *iface) {
	struct iface_info_port *port = (struct iface_info_port *)iface->info;

	if (evt != IFACE_EVENT_POST_ADD || iface->type_id != GR_IFACE_TYPE_PORT)
		return;

	lldp_iface_ctx[port->port_id].rx = lldp_default_conf.rx;
	lldp_iface_ctx[port->port_id].tx = lldp_default_conf.tx;

	iface_add_eth_addr(iface->id, &lldp_dst0);
	iface_add_eth_addr(iface->id, &lldp_dst1);
	iface_add_eth_addr(iface->id, &lldp_dst2);
}

static struct gr_module lldp_control_module = {
	.name = "lldp control",
	.init = lldp_control_init,
	.fini = lldp_control_fini,
};

static struct gr_api_handler lldp_set_iface_handler = {
	.name = "lldp set conf",
	.request_type = GR_LLDP_SET_IFACE_CONF,
	.callback = lldp_set_iface_conf,
};

static struct gr_api_handler lldp_set_global_handler = {
	.name = "lldp set global conf",
	.request_type = GR_LLDP_SET_GLOBAL_CONF,
	.callback = lldp_set_global_conf,
};

static struct gr_api_handler lldp_show_config_handler = {
	.name = "lldp show config",
	.request_type = GR_LLDP_SHOW_CONFIG,
	.callback = lldp_show_config,
};

static struct gr_api_handler lldp_show_neighbors_handler = {
	.name = "lldp show neighbors",
	.request_type = GR_LLDP_SHOW_NEIGH,
	.callback = lldp_show_neighbors,
};

static struct iface_event_handler lldp_iface_notify_handler = {
	.callback = lldp_iface_event,
};

RTE_INIT(lldp_control) {
	gr_register_api_handler(&lldp_set_iface_handler);
	gr_register_api_handler(&lldp_set_global_handler);
	gr_register_api_handler(&lldp_show_config_handler);
	gr_register_api_handler(&lldp_show_neighbors_handler);
	gr_register_module(&lldp_control_module);
	iface_event_register_handler(&lldp_iface_notify_handler);
};
