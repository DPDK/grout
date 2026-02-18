// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "port_mirror_priv.h"

#include <gr_api.h>
#include <gr_l2.h>
#include <gr_log.h>
#include <gr_vec.h>

#include <rte_ether.h>
#include <rte_mbuf.h>

#include <string.h>

struct port_mirroring port_mirrors[L2_MAX_BRIDGES];
struct mirror_stats mirror_stats_arr[L2_MAX_BRIDGES][RTE_MAX_LCORE];

int port_mirror_session_set(
	uint16_t bridge_id,
	uint16_t session_id,
	bool enabled,
	const uint16_t *source_ports,
	uint16_t num_sources,
	uint16_t dest_port,
	uint8_t direction,
	bool is_rspan,
	uint16_t rspan_vlan
) {
	struct mirror_session *session;
	struct port_mirroring *pm;

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	if (session_id == 0 || session_id > MAX_MIRROR_SESSIONS)
		return -EINVAL;
	if (num_sources > MAX_SOURCE_PORTS)
		return -EINVAL;
	if (dest_port >= L2_MAX_IFACES)
		return -EINVAL;
	if (direction == 0 || direction > GR_MIRROR_DIR_BOTH)
		return -EINVAL;

	pm = &port_mirrors[bridge_id];
	session = &pm->sessions[session_id - 1];

	gr_vec_free(session->source_ports);

	if (enabled && num_sources > 0) {
		for (uint16_t i = 0; i < num_sources; i++) {
			if (source_ports[i] >= L2_MAX_IFACES)
				continue;
			bool dup = false;
			for (uint16_t j = 0; j < gr_vec_len(session->source_ports); j++) {
				if (session->source_ports[j] == source_ports[i]) {
					dup = true;
					break;
				}
			}
			if (!dup)
				gr_vec_add(session->source_ports, source_ports[i]);
		}
	}

	session->session_id = session_id;
	session->enabled = enabled;
	session->dest_port = dest_port;
	session->direction = direction;
	session->is_rspan = is_rspan;
	session->rspan_vlan = rspan_vlan;

	pm->num_sessions = 0;
	for (uint16_t i = 0; i < MAX_MIRROR_SESSIONS; i++) {
		if (pm->sessions[i].enabled)
			pm->num_sessions++;
	}

	return 0;
}

int port_mirror_session_get(
	uint16_t bridge_id,
	uint16_t session_id,
	struct mirror_session *session
) {
	if (bridge_id >= L2_MAX_BRIDGES || session == NULL)
		return -EINVAL;
	if (session_id == 0 || session_id > MAX_MIRROR_SESSIONS)
		return -EINVAL;

	memcpy(session, &port_mirrors[bridge_id].sessions[session_id - 1], sizeof(*session));
	return 0;
}

int port_mirror_session_del(uint16_t bridge_id, uint16_t session_id) {
	struct mirror_session *session;
	struct port_mirroring *pm;

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	if (session_id == 0 || session_id > MAX_MIRROR_SESSIONS)
		return -EINVAL;

	pm = &port_mirrors[bridge_id];
	session = &pm->sessions[session_id - 1];

	gr_vec_free(session->source_ports);
	gr_vec_free(session->filter.vlans);
	memset(session, 0, sizeof(*session));

	pm->num_sessions = 0;
	for (uint16_t i = 0; i < MAX_MIRROR_SESSIONS; i++) {
		if (pm->sessions[i].enabled)
			pm->num_sessions++;
	}

	return 0;
}

int port_mirror_filter_set(
	uint16_t bridge_id,
	uint16_t session_id,
	bool enabled,
	const uint16_t *vlans,
	uint16_t num_vlans,
	uint16_t ether_type,
	const struct rte_ether_addr *src_mac,
	const struct rte_ether_addr *dst_mac
) {
	struct mirror_session *session;
	struct mirror_filter *filter;

	if (bridge_id >= L2_MAX_BRIDGES)
		return -EINVAL;
	if (session_id == 0 || session_id > MAX_MIRROR_SESSIONS)
		return -EINVAL;

	session = &port_mirrors[bridge_id].sessions[session_id - 1];
	if (!session->enabled)
		return -ENOENT;

	filter = &session->filter;

	gr_vec_free(filter->vlans);

	if (enabled && num_vlans > 0 && vlans != NULL) {
		for (uint16_t i = 0; i < num_vlans; i++) {
			if (vlans[i] <= 4094)
				gr_vec_add(filter->vlans, vlans[i]);
		}
	}

	filter->enabled = enabled;
	filter->ether_type = ether_type;

	if (src_mac != NULL) {
		rte_ether_addr_copy(src_mac, &filter->src_mac);
		filter->src_mac_set = true;
	} else {
		filter->src_mac_set = false;
	}

	if (dst_mac != NULL) {
		rte_ether_addr_copy(dst_mac, &filter->dst_mac);
		filter->dst_mac_set = true;
	} else {
		filter->dst_mac_set = false;
	}

	return 0;
}

struct mirror_stats *port_mirror_get_stats(uint16_t lcore_id, uint16_t bridge_id) {
	if (lcore_id >= RTE_MAX_LCORE || bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return &mirror_stats_arr[bridge_id][lcore_id];
}

bool port_mirror_should_mirror(
	uint16_t bridge_id,
	uint16_t iface_id,
	uint8_t direction,
	uint16_t *session_ids,
	uint16_t *num_sessions
) {
	struct port_mirroring *pm;

	if (bridge_id >= L2_MAX_BRIDGES || session_ids == NULL || num_sessions == NULL)
		return false;

	pm = &port_mirrors[bridge_id];
	*num_sessions = 0;

	if (pm->num_sessions == 0)
		return false;

	for (uint16_t i = 0; i < MAX_MIRROR_SESSIONS; i++) {
		struct mirror_session *s = &pm->sessions[i];

		if (!s->enabled)
			continue;
		if (!port_mirror_is_source(s, iface_id))
			continue;
		if ((s->direction & direction) == 0)
			continue;

		session_ids[*num_sessions] = s->session_id;
		(*num_sessions)++;

		if (*num_sessions >= MAX_MIRROR_SESSIONS)
			break;
	}

	return *num_sessions > 0;
}

bool port_mirror_filter_match(const struct mirror_filter *filter, const struct rte_mbuf *mbuf) {
	struct rte_ether_hdr *eth;
	uint16_t eth_type;

	if (filter == NULL || mbuf == NULL || !filter->enabled)
		return true;

	eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

	if (filter->ether_type != 0) {
		eth_type = rte_be_to_cpu_16(eth->ether_type);
		if (eth_type == RTE_ETHER_TYPE_VLAN) {
			struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
			eth_type = rte_be_to_cpu_16(vlan->eth_proto);
		}
		if (eth_type != filter->ether_type)
			return false;
	}

	if (filter->src_mac_set) {
		if (!rte_is_same_ether_addr(&eth->src_addr, &filter->src_mac))
			return false;
	}

	if (filter->dst_mac_set) {
		if (!rte_is_same_ether_addr(&eth->dst_addr, &filter->dst_mac))
			return false;
	}

	if (filter->vlans != NULL && gr_vec_len(filter->vlans) > 0) {
		if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_VLAN)
			return false;
		struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
		uint16_t vid = rte_be_to_cpu_16(vlan->vlan_tci) & 0x0FFF;
		bool match = false;
		for (uint16_t i = 0; i < gr_vec_len(filter->vlans); i++) {
			if (filter->vlans[i] == vid) {
				match = true;
				break;
			}
		}
		if (!match)
			return false;
	}

	return true;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out mirror_session_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mirror_session_req *req = request;

	int ret = port_mirror_session_set(
		req->bridge_id, req->session_id, req->enabled,
		req->source_ports, req->num_sources, req->dest_port,
		req->direction, req->is_rspan, req->rspan_vlan
	);

	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out mirror_session_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mirror_session_get_req *req = request;
	struct gr_l2_mirror_session_status *resp;
	struct mirror_session session;

	if (port_mirror_session_get(req->bridge_id, req->session_id, &session) < 0)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;
	resp->session_id = req->session_id;
	resp->enabled = session.enabled;
	resp->num_sources = gr_vec_len(session.source_ports);
	for (uint16_t i = 0; i < resp->num_sources && i < 16; i++)
		resp->source_ports[i] = session.source_ports[i];
	resp->dest_port = session.dest_port;
	resp->direction = session.direction;
	resp->is_rspan = session.is_rspan;
	resp->rspan_vlan = session.rspan_vlan;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out mirror_session_del_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mirror_session_del_req *req = request;
	int ret = port_mirror_session_del(req->bridge_id, req->session_id);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out mirror_filter_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mirror_filter_req *req = request;

	int ret = port_mirror_filter_set(
		req->bridge_id, req->session_id, req->enabled,
		req->vlans, req->num_vlans, req->ether_type,
		req->src_mac_set ? &req->src_mac : NULL,
		req->dst_mac_set ? &req->dst_mac : NULL
	);

	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out mirror_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_mirror_session_get_req *req = request;
	struct gr_l2_mirror_stats *resp;

	if (req->bridge_id >= L2_MAX_BRIDGES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct mirror_stats *st = port_mirror_get_stats(lcore, req->bridge_id);
		if (st == NULL)
			continue;
		resp->packets_mirrored += st->packets_mirrored;
		resp->packets_dropped += st->packets_dropped;
		resp->filter_matched += st->filter_matched;
		resp->filter_rejected += st->filter_rejected;
		resp->clone_failed += st->clone_failed;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler mirror_session_set_h = {
	.name = "port mirror session set",
	.request_type = GR_L2_MIRROR_SESSION_SET,
	.callback = mirror_session_set_cb,
};
static struct gr_api_handler mirror_session_get_h = {
	.name = "port mirror session get",
	.request_type = GR_L2_MIRROR_SESSION_GET,
	.callback = mirror_session_get_cb,
};
static struct gr_api_handler mirror_session_del_h = {
	.name = "port mirror session del",
	.request_type = GR_L2_MIRROR_SESSION_DEL,
	.callback = mirror_session_del_cb,
};
static struct gr_api_handler mirror_filter_set_h = {
	.name = "port mirror filter set",
	.request_type = GR_L2_MIRROR_FILTER_SET,
	.callback = mirror_filter_set_cb,
};
static struct gr_api_handler mirror_stats_get_h = {
	.name = "port mirror stats get",
	.request_type = GR_L2_MIRROR_STATS_GET,
	.callback = mirror_stats_get_cb,
};

RTE_INIT(port_mirror_constructor) {
	gr_register_api_handler(&mirror_session_set_h);
	gr_register_api_handler(&mirror_session_get_h);
	gr_register_api_handler(&mirror_session_del_h);
	gr_register_api_handler(&mirror_filter_set_h);
	gr_register_api_handler(&mirror_stats_get_h);
}
