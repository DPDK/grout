// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

// IPIP reconfig attributes
#define GR_IPIP_SET_LOCAL GR_BIT64(32)
#define GR_IPIP_SET_REMOTE GR_BIT64(33)

// Info for GR_IFACE_TYPE_IPIP interfaces
struct gr_iface_info_ipip {
	ip4_addr_t local;
	ip4_addr_t remote;
};
