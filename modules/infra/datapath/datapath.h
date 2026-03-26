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

static inline bool rate_limited_at(
	struct rate_limit_ctx *ctx,
	const uint16_t max_rate,
	const uint16_t nb_pkts,
	const uint64_t now,
	const uint64_t hz
) {
	uint64_t elapsed, add;

	assert(ctx != NULL);

	if (max_rate == 0)
		return false;

	elapsed = now - ctx->last_refill;
	if (elapsed >= hz) {
		// The bucket is full after a second.
		ctx->tokens = max_rate;
		ctx->last_refill = now;
	} else if ((add = elapsed * max_rate / hz) > 0) {
		ctx->tokens = RTE_MIN(ctx->tokens + add, (uint64_t)max_rate);
		// refill
		ctx->last_refill += add * hz / max_rate;
	}

	if (ctx->tokens == 0)
		return true;

	ctx->tokens -= RTE_MIN(ctx->tokens, nb_pkts);

	return false;
}

static inline bool
rate_limited(struct rate_limit_ctx *ctx, const uint16_t max_rate, const uint16_t nb_pkts) {
	return rate_limited_at(ctx, max_rate, nb_pkts, rte_rdtsc(), rte_get_tsc_hz());
}
