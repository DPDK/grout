// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "qos_priv.h"

#include <gr_api.h>
#include <gr_l2.h>
#include <gr_log.h>

#include <rte_cycles.h>
#include <rte_meter.h>

#include <string.h>

struct qos_port_config qos_configs[L2_MAX_IFACES];
struct qos_port_state qos_states[L2_MAX_IFACES][RTE_MAX_LCORE];
struct qos_stats qos_statistics[L2_MAX_IFACES][RTE_MAX_LCORE];

static const uint8_t default_dscp_to_cos[64] = {
	[0] = 0,  [8] = 1,  [10] = 1, [12] = 1, [14] = 1,
	[16] = 2, [18] = 2, [20] = 2, [22] = 2,
	[24] = 3, [26] = 3, [28] = 3, [30] = 3,
	[32] = 4, [34] = 4, [36] = 4, [38] = 4,
	[40] = 5, [44] = 5,
	[46] = 6, [48] = 6,
	[56] = 7,
};

int qos_port_set(
	uint16_t iface_id,
	bool enabled,
	uint8_t sched_mode,
	uint32_t port_rate_kbps,
	bool trust_cos,
	bool trust_dscp,
	uint8_t default_priority
) {
	struct qos_port_config *cfg;

	if (iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (sched_mode > GR_QOS_SCHED_DWRR)
		return -EINVAL;
	if (default_priority >= QOS_NUM_PRIORITIES)
		return -EINVAL;

	cfg = &qos_configs[iface_id];
	cfg->enabled = enabled;
	cfg->sched_mode = sched_mode;
	cfg->port_rate_limit_kbps = port_rate_kbps;
	cfg->trust_cos = trust_cos;
	cfg->trust_dscp = trust_dscp;
	cfg->default_priority = default_priority;

	if (cfg->dscp_to_cos[0] == 0 && cfg->dscp_to_cos[46] == 0)
		memcpy(cfg->dscp_to_cos, default_dscp_to_cos, sizeof(default_dscp_to_cos));

	for (int i = 0; i < 8; i++) {
		if (cfg->cos_to_cos[i] == 0)
			cfg->cos_to_cos[i] = i;
	}

	return 0;
}

int qos_port_get(uint16_t iface_id, struct qos_port_config *cfg) {
	if (iface_id >= L2_MAX_IFACES || cfg == NULL)
		return -EINVAL;

	memcpy(cfg, &qos_configs[iface_id], sizeof(*cfg));
	return 0;
}

int qos_queue_set(
	uint16_t iface_id,
	uint8_t priority,
	uint32_t rate_limit_kbps,
	uint32_t weight,
	uint32_t min_rate_kbps
) {
	struct qos_queue_config *q;

	if (iface_id >= L2_MAX_IFACES)
		return -EINVAL;
	if (priority >= QOS_NUM_PRIORITIES)
		return -EINVAL;
	if (weight == 0 || weight > 255)
		return -EINVAL;

	q = &qos_configs[iface_id].queues[priority];
	q->rate_limit_kbps = rate_limit_kbps;
	q->weight = weight;
	q->min_rate_kbps = min_rate_kbps;

	return 0;
}

int qos_dscp_map_set(uint16_t iface_id, const uint8_t dscp_to_cos[64]) {
	if (iface_id >= L2_MAX_IFACES || dscp_to_cos == NULL)
		return -EINVAL;

	for (int i = 0; i < 64; i++) {
		if (dscp_to_cos[i] >= QOS_NUM_PRIORITIES)
			return -EINVAL;
	}

	memcpy(qos_configs[iface_id].dscp_to_cos, dscp_to_cos, 64);
	return 0;
}

int qos_cos_remap_set(uint16_t iface_id, const uint8_t cos_to_cos[8]) {
	if (iface_id >= L2_MAX_IFACES || cos_to_cos == NULL)
		return -EINVAL;

	for (int i = 0; i < 8; i++) {
		if (cos_to_cos[i] >= QOS_NUM_PRIORITIES)
			return -EINVAL;
	}

	memcpy(qos_configs[iface_id].cos_to_cos, cos_to_cos, 8);
	return 0;
}

struct qos_stats *qos_get_stats(uint16_t lcore_id, uint16_t iface_id) {
	if (lcore_id >= RTE_MAX_LCORE || iface_id >= L2_MAX_IFACES)
		return NULL;
	return &qos_statistics[iface_id][lcore_id];
}

uint8_t qos_classify_packet(
	const struct qos_port_config *cfg,
	const struct rte_mbuf *mbuf,
	uint8_t *original_priority
) {
	struct rte_ether_hdr *eth;
	uint8_t priority = cfg->default_priority;

	if (original_priority)
		*original_priority = priority;

	if (cfg->trust_cos) {
		eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_VLAN) {
			struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
			uint8_t cos = (rte_be_to_cpu_16(vlan->vlan_tci) >> 13) & 0x07;
			if (cos > 0) {
				priority = cos;
				if (original_priority)
					*original_priority = cos;
			}
		}
	}

	if (cfg->trust_dscp) {
		eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
		uint16_t etype = rte_be_to_cpu_16(eth->ether_type);
		uint8_t *l3 = (uint8_t *)(eth + 1);
		if (etype == RTE_ETHER_TYPE_VLAN) {
			struct rte_vlan_hdr *vlan = (struct rte_vlan_hdr *)(eth + 1);
			etype = rte_be_to_cpu_16(vlan->eth_proto);
			l3 = (uint8_t *)(vlan + 1);
		}
		if (etype == RTE_ETHER_TYPE_IPV4) {
			struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3;
			uint8_t dscp = (ip->type_of_service >> 2) & 0x3F;
			if (dscp > 0) {
				priority = cfg->dscp_to_cos[dscp];
				if (original_priority)
					*original_priority = priority;
			}
		}
	}

	return priority;
}

#ifndef __GROUT_UNIT_TEST__
__attribute__((noinline)) enum rte_color qos_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
) {
	return rte_meter_trtcm_color_blind_check(m, p, time, pkt_len);
}
#endif

bool qos_meter_packet(
	uint16_t iface_id,
	uint16_t lcore_id,
	uint8_t priority,
	uint32_t packet_len
) {
	struct qos_port_config *cfg;
	struct qos_port_state *state;
	struct qos_stats *stats;
	uint64_t tsc;

	if (iface_id >= L2_MAX_IFACES || lcore_id >= RTE_MAX_LCORE)
		return true;

	cfg = &qos_configs[iface_id];
	state = &qos_states[iface_id][lcore_id];
	stats = &qos_statistics[iface_id][lcore_id];

	if (!cfg->enabled)
		return true;

	if (priority >= QOS_NUM_PRIORITIES)
		return true;

	tsc = rte_rdtsc();

	if (cfg->port_rate_limit_kbps > 0) {
		if (qos_meter_check(&state->port_meter, &state->port_profile, tsc, packet_len)
		    == RTE_COLOR_RED) {
			stats->port_dropped++;
			return false;
		}
	}

	if (cfg->queues[priority].rate_limit_kbps > 0) {
		struct qos_queue_state *qs = &state->queues[priority];
		if (qos_meter_check(&qs->meter, &qs->profile, tsc, packet_len)
		    == RTE_COLOR_RED) {
			stats->dropped[priority]++;
			return false;
		}
	}

	stats->tx[priority]++;
	return true;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out qos_port_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_port_req *req = request;

	int ret = qos_port_set(
		req->iface_id, req->enabled, req->sched_mode,
		req->port_rate_kbps, req->trust_cos, req->trust_dscp,
		req->default_priority
	);

	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out qos_port_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_port_req *req = request;
	struct gr_l2_qos_port_status *resp;
	struct qos_port_config cfg;

	if (qos_port_get(req->iface_id, &cfg) < 0)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->iface_id = req->iface_id;
	resp->enabled = cfg.enabled;
	resp->sched_mode = cfg.sched_mode;
	resp->port_rate_kbps = cfg.port_rate_limit_kbps;
	resp->trust_cos = cfg.trust_cos;
	resp->trust_dscp = cfg.trust_dscp;
	resp->default_priority = cfg.default_priority;
	memcpy(resp->dscp_to_cos, cfg.dscp_to_cos, sizeof(resp->dscp_to_cos));
	memcpy(resp->cos_to_cos, cfg.cos_to_cos, sizeof(resp->cos_to_cos));
	for (uint8_t i = 0; i < 8; i++) {
		resp->queues[i].rate_limit_kbps = cfg.queues[i].rate_limit_kbps;
		resp->queues[i].weight = cfg.queues[i].weight;
		resp->queues[i].min_rate_kbps = cfg.queues[i].min_rate_kbps;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out qos_queue_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_queue_req *req = request;
	int ret = qos_queue_set(
		req->iface_id, req->priority, req->rate_limit_kbps,
		req->weight, req->min_rate_kbps
	);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out qos_dscp_map_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_dscp_map_req *req = request;
	int ret = qos_dscp_map_set(req->iface_id, req->dscp_to_cos);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out qos_cos_remap_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_cos_remap_req *req = request;
	int ret = qos_cos_remap_set(req->iface_id, req->cos_to_cos);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out qos_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_qos_port_req *req = request;
	struct gr_l2_qos_stats *resp;

	if (req->iface_id >= L2_MAX_IFACES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->iface_id = req->iface_id;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct qos_stats *st = qos_get_stats(lcore, req->iface_id);
		if (st == NULL)
			continue;
		for (int i = 0; i < 8; i++) {
			resp->classified[i] += st->classified[i];
			resp->remarked[i] += st->remarked[i];
			resp->dropped[i] += st->dropped[i];
			resp->tx[i] += st->tx[i];
		}
		resp->port_dropped += st->port_dropped;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler qos_port_set_h = {
	.name = "qos port set",
	.request_type = GR_L2_QOS_PORT_SET,
	.callback = qos_port_set_cb,
};
static struct gr_api_handler qos_port_get_h = {
	.name = "qos port get",
	.request_type = GR_L2_QOS_PORT_GET,
	.callback = qos_port_get_cb,
};
static struct gr_api_handler qos_queue_set_h = {
	.name = "qos queue set",
	.request_type = GR_L2_QOS_QUEUE_SET,
	.callback = qos_queue_set_cb,
};
static struct gr_api_handler qos_dscp_map_set_h = {
	.name = "qos dscp map set",
	.request_type = GR_L2_QOS_DSCP_MAP_SET,
	.callback = qos_dscp_map_set_cb,
};
static struct gr_api_handler qos_cos_remap_set_h = {
	.name = "qos cos remap set",
	.request_type = GR_L2_QOS_COS_REMAP_SET,
	.callback = qos_cos_remap_set_cb,
};
static struct gr_api_handler qos_stats_get_h = {
	.name = "qos stats get",
	.request_type = GR_L2_QOS_STATS_GET,
	.callback = qos_stats_get_cb,
};

RTE_INIT(qos_constructor) {
	for (uint16_t i = 0; i < L2_MAX_IFACES; i++) {
		for (uint8_t j = 0; j < 8; j++)
			qos_configs[i].cos_to_cos[j] = j;
	}

	gr_register_api_handler(&qos_port_set_h);
	gr_register_api_handler(&qos_port_get_h);
	gr_register_api_handler(&qos_queue_set_h);
	gr_register_api_handler(&qos_dscp_map_set_h);
	gr_register_api_handler(&qos_cos_remap_set_h);
	gr_register_api_handler(&qos_stats_get_h);
}
