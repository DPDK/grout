// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Harrison Caldicott

#pragma once

#include <rte_mbuf.h>

#include <stdint.h>

typedef enum : uint8_t {
	GR_MBUF_FLOW_HASH_L2,
	GR_MBUF_FLOW_HASH_L3_L4,
	GR_MBUF_FLOW_HASH_RSS,
} gr_mbuf_flow_hash_mode_t;

// Return a stable packet-flow hash. The packet data must start with an
// Ethernet header. RSS mode uses a hardware hash when present and falls back
// to a software L3/L4 hash for virtual devices without RSS.
uint32_t gr_mbuf_flow_hash(const struct rte_mbuf *, gr_mbuf_flow_hash_mode_t);
