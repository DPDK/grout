// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Fabien Dupont

#include "storm_control_priv.h"

#include <gr_api.h>
#include <gr_l2.h>
#include <gr_log.h>

#include <rte_cycles.h>
#include <rte_meter.h>

#include <string.h>

struct storm_control_config storm_control_configs[L2_MAX_IFACES];
struct storm_control_state storm_control_states[L2_MAX_IFACES][RTE_MAX_LCORE];
struct storm_control_stats storm_control_stats_arr[L2_MAX_IFACES][RTE_MAX_LCORE];

static inline uint64_t rate_to_bytes_per_sec(uint64_t rate_kbps, bool use_pps) {
	if (rate_kbps == 0)
		return UINT64_MAX;
	if (use_pps)
		return rate_kbps * 1500;
	return (rate_kbps * 1000) / 8;
}

static int init_meter_profile(
	struct rte_meter_trtcm_profile *profile,
	uint64_t rate_kbps,
	bool use_pps
) {
	struct rte_meter_trtcm_params params;
	uint64_t cir = rate_to_bytes_per_sec(rate_kbps, use_pps);

	if (cir == UINT64_MAX) {
		params.cir = UINT64_MAX / 2;
		params.pir = UINT64_MAX / 2;
		params.cbs = UINT64_MAX / 2;
		params.pbs = UINT64_MAX / 2;
	} else {
		params.cir = cir;
		params.pir = cir + (cir / 2);
		params.cbs = cir * 2;
		params.pbs = cir * 2;
	}

	return rte_meter_trtcm_profile_config(profile, &params);
}

int storm_control_init_meters(uint16_t iface_id, uint16_t lcore_id) {
	struct storm_control_config *cfg;
	struct storm_control_state *state;
	int ret;

	if (iface_id >= L2_MAX_IFACES || lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	cfg = &storm_control_configs[iface_id];
	state = &storm_control_states[iface_id][lcore_id];

	if (!cfg->enabled) {
		memset(state, 0, sizeof(*state));
		return 0;
	}

	ret = init_meter_profile(&state->bcast_profile, cfg->bcast_rate_kbps, cfg->use_pps);
	if (ret < 0)
		return ret;
	ret = rte_meter_trtcm_config(&state->bcast_meter, &state->bcast_profile);
	if (ret < 0)
		return ret;

	ret = init_meter_profile(&state->mcast_profile, cfg->mcast_rate_kbps, cfg->use_pps);
	if (ret < 0)
		return ret;
	ret = rte_meter_trtcm_config(&state->mcast_meter, &state->mcast_profile);
	if (ret < 0)
		return ret;

	ret = init_meter_profile(
		&state->unknown_uc_profile, cfg->unknown_uc_rate_kbps, cfg->use_pps
	);
	if (ret < 0)
		return ret;
	ret = rte_meter_trtcm_config(&state->unknown_uc_meter, &state->unknown_uc_profile);
	if (ret < 0)
		return ret;

	state->last_update_tsc = rte_rdtsc();
	state->bcast_violations = 0;
	state->mcast_violations = 0;
	state->unknown_uc_violations = 0;
	state->is_shutdown = false;

	return 0;
}

#ifndef __GROUT_UNIT_TEST__
__attribute__((noinline)) enum rte_color storm_control_meter_check(
	struct rte_meter_trtcm *m,
	struct rte_meter_trtcm_profile *p,
	uint64_t time,
	uint32_t pkt_len
) {
	return rte_meter_trtcm_color_blind_check(m, p, time, pkt_len);
}
#endif

bool storm_control_meter_packet(
	uint16_t iface_id,
	uint16_t lcore_id,
	enum storm_traffic_type traffic_type,
	uint32_t packet_len
) {
	struct storm_control_config *cfg;
	struct storm_control_state *state;
	struct storm_control_stats *stats;
	struct rte_meter_trtcm *meter;
	struct rte_meter_trtcm_profile *profile;
	uint8_t *violations;
	uint64_t *passed, *dropped;
	enum rte_color color;

	if (iface_id >= L2_MAX_IFACES || lcore_id >= RTE_MAX_LCORE)
		return true;

	cfg = &storm_control_configs[iface_id];
	state = &storm_control_states[iface_id][lcore_id];
	stats = &storm_control_stats_arr[iface_id][lcore_id];

	if (!cfg->enabled)
		return true;

	if (state->is_shutdown)
		return false;

	switch (traffic_type) {
	case STORM_TRAFFIC_BROADCAST:
		meter = &state->bcast_meter;
		profile = &state->bcast_profile;
		violations = &state->bcast_violations;
		passed = &stats->bcast_passed;
		dropped = &stats->bcast_dropped;
		if (cfg->bcast_rate_kbps == 0)
			return true;
		break;
	case STORM_TRAFFIC_MULTICAST:
		meter = &state->mcast_meter;
		profile = &state->mcast_profile;
		violations = &state->mcast_violations;
		passed = &stats->mcast_passed;
		dropped = &stats->mcast_dropped;
		if (cfg->mcast_rate_kbps == 0)
			return true;
		break;
	case STORM_TRAFFIC_UNKNOWN_UC:
		meter = &state->unknown_uc_meter;
		profile = &state->unknown_uc_profile;
		violations = &state->unknown_uc_violations;
		passed = &stats->unknown_uc_passed;
		dropped = &stats->unknown_uc_dropped;
		if (cfg->unknown_uc_rate_kbps == 0)
			return true;
		break;
	default:
		return true;
	}

	color = storm_control_meter_check(meter, profile, rte_rdtsc(), packet_len);

	if (color == RTE_COLOR_GREEN) {
		(*passed)++;
		*violations = 0;
		return true;
	}

	(*dropped)++;
	(*violations)++;

	if (cfg->shutdown_on_violation && *violations >= cfg->violation_threshold) {
		state->is_shutdown = true;
		stats->shutdown_events++;
		LOG(WARNING,
		    "storm_control: interface %u shutdown due to %s violations",
		    iface_id,
		    traffic_type == STORM_TRAFFIC_BROADCAST      ? "broadcast"
			: traffic_type == STORM_TRAFFIC_MULTICAST ? "multicast"
								  : "unknown-unicast");
	}

	return false;
}

int storm_control_set_config(
	uint16_t iface_id,
	bool enabled,
	uint64_t bcast_rate_kbps,
	uint64_t mcast_rate_kbps,
	uint64_t unknown_uc_rate_kbps,
	bool use_pps,
	bool shutdown_on_violation,
	uint8_t violation_threshold
) {
	struct storm_control_config *cfg;

	if (iface_id >= L2_MAX_IFACES)
		return -EINVAL;

	cfg = &storm_control_configs[iface_id];
	cfg->enabled = enabled;
	cfg->bcast_rate_kbps = bcast_rate_kbps;
	cfg->mcast_rate_kbps = mcast_rate_kbps;
	cfg->unknown_uc_rate_kbps = unknown_uc_rate_kbps;
	cfg->use_pps = use_pps;
	cfg->shutdown_on_violation = shutdown_on_violation;
	cfg->violation_threshold = violation_threshold > 0 ? violation_threshold : 5;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		storm_control_init_meters(iface_id, lcore);

	return 0;
}

int storm_control_get_config(uint16_t iface_id, struct storm_control_config *cfg) {
	if (iface_id >= L2_MAX_IFACES || cfg == NULL)
		return -EINVAL;

	memcpy(cfg, &storm_control_configs[iface_id], sizeof(*cfg));
	return 0;
}

int storm_control_reenable_interface(uint16_t iface_id) {
	if (iface_id >= L2_MAX_IFACES)
		return -EINVAL;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		storm_control_states[iface_id][lcore].is_shutdown = false;
		storm_control_states[iface_id][lcore].bcast_violations = 0;
		storm_control_states[iface_id][lcore].mcast_violations = 0;
		storm_control_states[iface_id][lcore].unknown_uc_violations = 0;
	}

	return 0;
}

// API handlers ////////////////////////////////////////////////////////////////

static struct api_out storm_control_set_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_storm_control_req *req = request;

	int ret = storm_control_set_config(
		req->iface_id, req->enabled, req->bcast_rate_kbps,
		req->mcast_rate_kbps, req->unknown_uc_rate_kbps,
		req->use_pps, req->shutdown_on_violation, req->violation_threshold
	);

	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out storm_control_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_storm_control_get_req *req = request;
	struct gr_l2_storm_control_status *resp;
	struct storm_control_config cfg;

	if (storm_control_get_config(req->iface_id, &cfg) < 0)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->iface_id = req->iface_id;
	resp->enabled = cfg.enabled;
	resp->bcast_rate_kbps = cfg.bcast_rate_kbps;
	resp->mcast_rate_kbps = cfg.mcast_rate_kbps;
	resp->unknown_uc_rate_kbps = cfg.unknown_uc_rate_kbps;
	resp->use_pps = cfg.use_pps;
	resp->shutdown_on_violation = cfg.shutdown_on_violation;
	resp->violation_threshold = cfg.violation_threshold;

	resp->is_shutdown = false;
	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (storm_control_states[req->iface_id][lcore].is_shutdown) {
			resp->is_shutdown = true;
			break;
		}
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out storm_control_reenable_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_storm_control_reenable_req *req = request;
	int ret = storm_control_reenable_interface(req->iface_id);
	return api_out(ret < 0 ? -ret : 0, 0, NULL);
}

static struct api_out storm_control_stats_get_cb(const void *request, struct api_ctx *) {
	const struct gr_l2_storm_control_get_req *req = request;
	struct gr_l2_storm_control_stats *resp;

	if (req->iface_id >= L2_MAX_IFACES)
		return api_out(EINVAL, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->iface_id = req->iface_id;

	for (uint16_t lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct storm_control_stats *st = storm_control_get_stats(lcore, req->iface_id);
		if (st == NULL)
			continue;
		resp->bcast_passed += st->bcast_passed;
		resp->bcast_dropped += st->bcast_dropped;
		resp->mcast_passed += st->mcast_passed;
		resp->mcast_dropped += st->mcast_dropped;
		resp->unknown_uc_passed += st->unknown_uc_passed;
		resp->unknown_uc_dropped += st->unknown_uc_dropped;
		resp->shutdown_events += st->shutdown_events;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct gr_api_handler storm_control_set_h = {
	.name = "storm control set",
	.request_type = GR_L2_STORM_CONTROL_SET,
	.callback = storm_control_set_cb,
};
static struct gr_api_handler storm_control_get_h = {
	.name = "storm control get",
	.request_type = GR_L2_STORM_CONTROL_GET,
	.callback = storm_control_get_cb,
};
static struct gr_api_handler storm_control_reenable_h = {
	.name = "storm control reenable",
	.request_type = GR_L2_STORM_CONTROL_REENABLE,
	.callback = storm_control_reenable_cb,
};
static struct gr_api_handler storm_control_stats_get_h = {
	.name = "storm control stats get",
	.request_type = GR_L2_STORM_CONTROL_STATS_GET,
	.callback = storm_control_stats_get_cb,
};

RTE_INIT(storm_control_constructor) {
	gr_register_api_handler(&storm_control_set_h);
	gr_register_api_handler(&storm_control_get_h);
	gr_register_api_handler(&storm_control_reenable_h);
	gr_register_api_handler(&storm_control_stats_get_h);
}
