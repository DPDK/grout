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

enum gr_nat_requests : uint32_t {
	GR_DNAT44_ADD = GR_MSG_TYPE(GR_NAT_MODULE, 0x0001),
	GR_DNAT44_DEL,
	GR_DNAT44_LIST,
	GR_SNAT44_ADD,
	GR_SNAT44_DEL,
	GR_SNAT44_LIST,
};

// dnat44 //////////////////////////////////////////////////////////////////////

// DNAT nexthop information for stateless destination address translation.
struct gr_nexthop_info_dnat {
	ip4_addr_t match;
	ip4_addr_t replace;
};

// DNAT44 policy for stateless destination address translation.
struct gr_dnat44_policy {
	uint16_t iface_id;
	ip4_addr_t match;
	ip4_addr_t replace;
};

// Add a stateless DNAT44 policy.
struct gr_dnat44_add_req {
	struct gr_dnat44_policy policy;
	bool exist_ok;
};

GR_REQ(GR_DNAT44_ADD, struct gr_dnat44_add_req, struct gr_empty);

// Delete a stateless DNAT44 policy.
struct gr_dnat44_del_req {
	uint16_t iface_id;
	ip4_addr_t match;
	bool missing_ok;
};

GR_REQ(GR_DNAT44_DEL, struct gr_dnat44_del_req, struct gr_empty);

// List DNAT44 policies.
struct gr_dnat44_list_req {
	uint16_t vrf_id;
};

GR_REQ_STREAM(GR_DNAT44_LIST, struct gr_dnat44_list_req, struct gr_dnat44_policy);

// snat44 //////////////////////////////////////////////////////////////////////

// SNAT44 policy for source address translation (requires connection tracking).
struct gr_snat44_policy {
	uint16_t iface_id;
	struct ip4_net net;
	ip4_addr_t replace;
};

// Add a SNAT44 policy (requires connection tracking to be enabled).
struct gr_snat44_add_req {
	struct gr_snat44_policy policy;
	bool exist_ok;
};

GR_REQ(GR_SNAT44_ADD, struct gr_snat44_add_req, struct gr_empty);

// Delete a SNAT44 policy.
struct gr_snat44_del_req {
	struct gr_snat44_policy policy;
	bool missing_ok;
};

GR_REQ(GR_SNAT44_DEL, struct gr_snat44_del_req, struct gr_empty);

// List all SNAT44 policies.
GR_REQ_STREAM(GR_SNAT44_LIST, struct gr_empty, struct gr_snat44_policy);
