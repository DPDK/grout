// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

// NB: IPIP tunnels are managed using GR_INFRA_IFACE_* messages from gr_infra.h

// IPIP interface reconfiguration attributes.
#define GR_IPIP_SET_LOCAL GR_BIT64(32) // Update local endpoint address.
#define GR_IPIP_SET_REMOTE GR_BIT64(33) // Update remote endpoint address.

// Configuration information for GR_IFACE_TYPE_IPIP tunnel interfaces.
// Used with GR_INFRA_IFACE_ADD and GR_INFRA_IFACE_SET from gr_infra.h.
struct gr_iface_info_ipip {
	ip4_addr_t local; // Local tunnel endpoint (must be routable).
	ip4_addr_t remote; // Remote tunnel endpoint (must be routable and != local).
};
