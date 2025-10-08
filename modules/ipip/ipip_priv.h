// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_ipip.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <rte_common.h>

#include <stdalign.h>
#include <stdint.h>

GR_IFACE_INFO(GR_IFACE_TYPE_IPIP, iface_info_ipip, { BASE(gr_iface_info_ipip); });

struct iface *ipip_get_iface(ip4_addr_t local, ip4_addr_t remote, uint16_t vrf_id);

struct trace_ipip_data {
	uint16_t iface_id;
};

int trace_ipip_format(char *buf, size_t len, const void *data, size_t data_len);
