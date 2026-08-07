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
	uint16_t add;

	assert(ctx != NULL);

	if (max_rate == 0)
		return false;

	add = (now - ctx->last_refill) * max_rate / rte_get_tsc_hz();
	if (add > 0) {
		ctx->tokens = RTE_MIN((uint32_t)ctx->tokens + add, (uint32_t)max_rate);
		ctx->last_refill = now;
	}

	if (ctx->tokens == 0)
		return true;

	ctx->tokens -= RTE_MIN(ctx->tokens, nb_pkts);

	return false;
}
