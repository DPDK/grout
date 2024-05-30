// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_API_IPIP
#define _BR_API_IPIP

#include <br_api.h>
#include <br_bitops.h>
#include <br_infra.h>
#include <br_macro.h>
#include <br_net_types.h>

#define BR_IFACE_TYPE_IPIP 0x0003

// IPIP reconfig attributes
#define BR_IPIP_SET_LOCAL BR_BIT64(32)
#define BR_IPIP_SET_REMOTE BR_BIT64(33)

// Info for BR_IFACE_TYPE_IPIP interfaces
struct br_iface_info_ipip {
	ip4_addr_t local;
	ip4_addr_t remote;
};

static_assert(sizeof(struct br_iface_info_ipip) <= MEMBER_SIZE(struct br_iface, info));

#endif
