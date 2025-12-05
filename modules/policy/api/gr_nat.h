// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdbool.h>
#include <stdint.h>

#define GR_NAT_MODULE 0x0bad

// dnat44 //////////////////////////////////////////////////////////////////////

// DNAT nexthop information for stateless destination address translation.
struct gr_nexthop_info_dnat {
	ip4_addr_t match; // Original destination address to match.
	ip4_addr_t replace; // Replacement destination address.
};

// DNAT44 policy for stateless destination address translation.
struct gr_dnat44_policy {
	uint16_t iface_id; // Input interface where policy applies.
	ip4_addr_t match; // Destination address to match.
	ip4_addr_t replace; // Replacement destination address.
};

// Add a stateless DNAT44 policy.
#define GR_DNAT44_ADD REQUEST_TYPE(GR_NAT_MODULE, 0x0001)

struct gr_dnat44_add_req {
	struct gr_dnat44_policy policy;
	bool exist_ok; // Do not fail if policy already exists.
};

// struct gr_dnat44_add_resp { };

// Delete a stateless DNAT44 policy.
#define GR_DNAT44_DEL REQUEST_TYPE(GR_NAT_MODULE, 0x0002)

struct gr_dnat44_del_req {
	uint16_t iface_id; // Interface where policy is configured.
	ip4_addr_t match; // Destination address that was being matched.
	bool missing_ok; // Do not fail if policy does not exist.
};

// struct gr_dnat44_del_resp { };

// List DNAT44 policies.
#define GR_DNAT44_LIST REQUEST_TYPE(GR_NAT_MODULE, 0x0003)

struct gr_dnat44_list_req {
	uint16_t vrf_id; // Filter by VRF (use GR_VRF_ID_ALL for all VRFs).
};

STREAM_RESP(struct gr_dnat44_policy);

// snat44 //////////////////////////////////////////////////////////////////////

// SNAT44 policy for source address translation (requires connection tracking).
struct gr_snat44_policy {
	uint16_t iface_id; // Output interface where policy applies.
	struct ip4_net net; // Source address subnet to match.
	ip4_addr_t replace; // Replacement source address.
};

// Add a SNAT44 policy (requires connection tracking to be enabled).
#define GR_SNAT44_ADD REQUEST_TYPE(GR_NAT_MODULE, 0x0011)

struct gr_snat44_add_req {
	struct gr_snat44_policy policy;
	bool exist_ok; // Do not fail if policy already exists.
};

// struct gr_snat44_add_resp { };

// Delete a SNAT44 policy.
#define GR_SNAT44_DEL REQUEST_TYPE(GR_NAT_MODULE, 0x0012)

struct gr_snat44_del_req {
	struct gr_snat44_policy policy; // Policy to delete (must match exactly).
	bool missing_ok; // Do not fail if policy does not exist.
};

// struct gr_snat44_del_resp { };

// List all SNAT44 policies.
#define GR_SNAT44_LIST REQUEST_TYPE(GR_NAT_MODULE, 0x0013)

// struct gr_snat44_list_req { };

STREAM_RESP(struct gr_snat44_policy);
