// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_net_types.h>

#include <stdint.h>

struct trace_vxlan_data {
	rte_be32_t vni;
	struct l3_addr vtep;
};

int trace_vxlan_format(char *buf, size_t len, const void *data, size_t data_len);
