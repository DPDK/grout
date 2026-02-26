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

struct fdb_stats l2_fdb_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static struct api_out fdb_stats_get(const void *request, struct api_ctx *) {
	const struct gr_l2_fdb_stats_get_req *req = request;
	struct gr_l2_fdb_stats *resp;

	const struct iface *iface = iface_from_id(req->bridge_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	resp = calloc(1, sizeof(*resp));
	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->bridge_id = req->bridge_id;

	for (unsigned lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		struct fdb_stats *fs = fdb_get_stats(req->bridge_id, lcore_id);
		if (fs == NULL)
			continue;
		resp->hit += fs->hit;
		resp->miss += fs->miss;
		resp->flood += fs->flood;
	}

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out fdb_stats_reset(const void *request, struct api_ctx *) {
	const struct gr_l2_fdb_stats_reset_req *req = request;

	const struct iface *iface = iface_from_id(req->bridge_id);
	if (iface == NULL || iface->type != GR_IFACE_TYPE_BRIDGE)
		return api_out(ENOENT, 0, NULL);

	if (req->bridge_id < L2_MAX_BRIDGES)
		memset(l2_fdb_stats[req->bridge_id], 0, sizeof(l2_fdb_stats[0]));

	return api_out(0, 0, NULL);
}

static struct gr_api_handler fdb_stats_get_handler = {
	.name = "fdb stats get",
	.request_type = GR_L2_FDB_STATS_GET,
	.callback = fdb_stats_get,
};

static struct gr_api_handler fdb_stats_reset_handler = {
	.name = "fdb stats reset",
	.request_type = GR_L2_FDB_STATS_RESET,
	.callback = fdb_stats_reset,
};

RTE_INIT(fdb_stats_constructor) {
	gr_register_api_handler(&fdb_stats_get_handler);
	gr_register_api_handler(&fdb_stats_reset_handler);
}
