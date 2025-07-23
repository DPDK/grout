// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Maxime Leroy

#pragma once

#include <gr_api.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#define GR_VRF_MODULE 0xfaaf

struct gr_vrf_route_key {
	union {
		struct ip4_net dest4;
		struct ip6_net dest6;
	};
	bool is_dest6;
	uint16_t vrf_id;
};

struct gr_vrf_route {
	struct gr_vrf_route_key key;
	uint16_t out_vrf_id;
};

#define GR_VRF_ROUTE_ADD REQUEST_TYPE(GR_VRF_MODULE, 0x0001)

struct gr_vrf_route_add_req {
	uint8_t exist_ok;
	gr_nh_origin_t origin;
	struct gr_vrf_route r;
};

#define GR_VRF_ROUTE_DEL REQUEST_TYPE(GR_VRF_MODULE, 0x0002)

struct gr_vrf_route_del_req {
	struct gr_vrf_route_key key;
	uint8_t missing_ok;
};

#define GR_VRF_ROUTE_LIST REQUEST_TYPE(GR_VRF_MODULE, 0x0004)

struct gr_vrf_route_list_req {
	uint16_t vrf_id;
};

struct gr_vrf_route_list_resp {
	uint16_t n_route;
	struct gr_vrf_route route[/* n_route */];
};
