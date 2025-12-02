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

struct gr_nexthop_info_dnat {
	ip4_addr_t match;
	ip4_addr_t replace;
};

struct gr_dnat44_policy {
	uint16_t iface_id;
	ip4_addr_t match;
	ip4_addr_t replace;
};

#define GR_DNAT44_ADD REQUEST_TYPE(GR_NAT_MODULE, 0x0001)

struct gr_dnat44_add_req {
	struct gr_dnat44_policy policy;
	bool exist_ok;
};

// struct gr_dnat44_add_resp { };

#define GR_DNAT44_DEL REQUEST_TYPE(GR_NAT_MODULE, 0x0002)

struct gr_dnat44_del_req {
	uint16_t iface_id;
	ip4_addr_t match;
	bool missing_ok;
};

// struct gr_dnat44_del_resp { };

#define GR_DNAT44_LIST REQUEST_TYPE(GR_NAT_MODULE, 0x0003)

struct gr_dnat44_list_req {
	uint16_t vrf_id;
};

STREAM_RESP(struct gr_dnat44_policy);

// snat44 //////////////////////////////////////////////////////////////////////

struct gr_snat44_policy {
	uint16_t iface_id;
	struct ip4_net net;
	ip4_addr_t replace;
};

#define GR_SNAT44_ADD REQUEST_TYPE(GR_NAT_MODULE, 0x0011)

struct gr_snat44_add_req {
	struct gr_snat44_policy policy;
	bool exist_ok;
};

// struct gr_snat44_add_resp { };

#define GR_SNAT44_DEL REQUEST_TYPE(GR_NAT_MODULE, 0x0012)

struct gr_snat44_del_req {
	struct gr_snat44_policy policy;
	bool missing_ok;
};

// struct gr_snat44_del_resp { };

#define GR_SNAT44_LIST REQUEST_TYPE(GR_NAT_MODULE, 0x0013)

// struct gr_snat44_list_req { };

STREAM_RESP(struct gr_snat44_policy);
