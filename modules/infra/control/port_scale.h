// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Maxime Leroy, Free Mobile

#pragma once

#include "port.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// allowed_n may be a proper subset of [1..max_n] (DPAA2 has a discrete
// list; Intel/Mellanox accept any value).
struct port_scale_caps {
	uint16_t max_n;
	uint16_t *allowed_n; // sorted ascending, free with _free()
	size_t allowed_count;
	bool supports_scale;
};

int port_scale_caps_get(struct iface_info_port *p, struct port_scale_caps *out);
// Same, but compute caps for a target RX queue count (n_rxq == 0 uses the live
// HW count). Lets a pending reconfig validate against the count it will apply.
int port_scale_caps_get_n(struct iface_info_port *p, uint16_t n_rxq, struct port_scale_caps *out);
void port_scale_caps_free(struct port_scale_caps *caps);

// Drop allowed_n entries not aligned on cluster, keeping scaling steps on
// cache-sharing group boundaries. cluster <= 1 is a no-op. Updates
// allowed_count and supports_scale (false once <= 1 value remains).
void port_scale_caps_filter_cluster(struct port_scale_caps *caps, uint16_t cluster);

// Returns the same value at the boundary.
uint16_t port_scale_caps_next(const struct port_scale_caps *caps, uint16_t cur);
uint16_t port_scale_caps_prev(const struct port_scale_caps *caps, uint16_t cur);

// Snap n onto the grid: the largest allowed_n <= n, or the smallest allowed_n
// if n is below the grid. Returns n unchanged when the grid is empty.
uint16_t port_scale_caps_clamp(const struct port_scale_caps *caps, uint16_t n);

// Reprogram HW RETA to dispatch only on queues [0..n-1] (uniform i % n).
// n must be in caps.allowed_n.
int port_scale_apply(struct iface_info_port *p, uint16_t n);
