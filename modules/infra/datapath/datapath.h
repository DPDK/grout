// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <rte_cycles.h>

#include <stdint.h>

void *gr_datapath_loop(void *priv);

struct rate_limit_ctx {
	uint16_t tokens;
	uint64_t last_refill;
} __attribute__((packed));

static inline bool
rate_limited(struct rate_limit_ctx *ctx, const uint16_t max_rate, const uint16_t nb_pkts) {
	uint64_t now = rte_rdtsc();
	assert(ctx != NULL);

	if (max_rate == 0)
		return false;

	if (now - ctx->last_refill >= rte_get_tsc_hz()) {
		ctx->tokens = max_rate;
		ctx->last_refill = now;
	} else if (ctx->tokens == 0) {
		return true;
	}
	ctx->tokens -= RTE_MIN(ctx->tokens, nb_pkts);

	return false;
}
