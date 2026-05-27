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
void port_scale_caps_free(struct port_scale_caps *caps);

// Returns the same value at the boundary.
uint16_t port_scale_caps_next(const struct port_scale_caps *caps, uint16_t cur);
uint16_t port_scale_caps_prev(const struct port_scale_caps *caps, uint16_t cur);

// Reprogram HW RETA to dispatch only on queues [0..n-1] (uniform i % n).
// n must be in caps.allowed_n.
int port_scale_apply(struct iface_info_port *p, uint16_t n);
