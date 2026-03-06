// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_api.h>
#include <gr_config.h>
#include <gr_module.h>

#include <rte_common.h>

static struct api_out log_packets_set(const void *request, struct api_ctx *) {
	const struct gr_log_packets_set_req *req = request;
	gr_config.log_packets = req->enabled;
	return api_out(0, 0, NULL);
}

RTE_INIT(log_api_init) {
	gr_api_handler(GR_LOG_PACKETS_SET, log_packets_set);
}
