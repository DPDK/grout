// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_api.h>
#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_module.h>

#include <rte_lcore.h>

#include <stdlib.h>
#include <string.h>

static struct api_out l2_stats_get(const void *request, struct api_ctx *) {
	const struct gr_l2_stats_get_req *req = request;
	const struct iface *iface;
	struct gr_l2_bridge_stats *resp;

	iface = iface_from_id(req->bridge_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct bridge_stats *bs = bridge_get_stats(req->bridge_id, lcore_id);
		struct fdb_stats *fs = fdb_get_stats(req->bridge_id, lcore_id);

		if (bs == NULL || fs == NULL)
			continue;

		resp->unicast_fwd += bs->unicast_fwd;
		resp->broadcast_fwd += bs->broadcast_fwd;
		resp->multicast_fwd += bs->multicast_fwd;
		resp->flood_fwd += bs->flood_fwd;
		resp->no_fdb_drop += bs->no_fdb_drop;
		resp->hairpin_drop += bs->hairpin_drop;
		resp->iface_down_drop += bs->iface_down_drop;
		resp->learn_ok += bs->learn_ok;
		resp->learn_update += bs->learn_update;
		resp->learn_fail += bs->learn_fail;
		resp->learn_skip += bs->learn_skip;
		resp->learn_limit_bridge += bs->learn_limit_bridge;
		resp->learn_limit_iface += bs->learn_limit_iface;
		resp->learn_shutdown += bs->learn_shutdown;
		resp->rstp_blocking_drop += bs->rstp_blocking_drop;
		resp->rstp_learn_skip += bs->rstp_learn_skip;
		resp->fdb_lookup_hit += fs->lookup_hit;
		resp->fdb_lookup_miss += fs->lookup_miss;
		resp->fdb_entries_aged += fs->entries_aged;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out l2_stats_reset(const void *request, struct api_ctx *) {
	const struct gr_l2_stats_reset_req *req = request;
	const struct iface *iface;

	iface = iface_from_id(req->bridge_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	if (req->bridge_id < L2_MAX_BRIDGES) {
		memset(l2_bridge_stats[req->bridge_id], 0, sizeof(l2_bridge_stats[0]));
		memset(l2_fdb_stats[req->bridge_id], 0, sizeof(l2_fdb_stats[0]));
	}

	return api_out(0, 0, NULL);
}

static struct gr_api_handler l2_stats_get_handler = {
	.name = "l2 stats get",
	.request_type = GR_L2_STATS_GET,
	.callback = l2_stats_get,
};

static struct gr_api_handler l2_stats_reset_handler = {
	.name = "l2 stats reset",
	.request_type = GR_L2_STATS_RESET,
	.callback = l2_stats_reset,
};

RTE_INIT(l2_stats_constructor) {
	gr_register_api_handler(&l2_stats_get_handler);
	gr_register_api_handler(&l2_stats_reset_handler);
}
