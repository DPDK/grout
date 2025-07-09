// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include <gr_api.h>
#include <gr_net_types.h>

#define GR_SRV6_MODULE 0xfeef

// sr routes //////////////////////////////////////////////////////

#define GR_SRV6_ROUTE_SEGLIST_COUNT_MAX 60

// SRv6 Route Headend Behaviors Signaling (rfc8986 8.4)
typedef enum : uint8_t {
	SR_H_ENCAPS,
	SR_H_ENCAPS_RED,

	SR_H_ENCAPS_MAX,
} gr_srv6_encap_behavior_t;

struct gr_srv6_route_key {
	union {
		struct ip4_net dest4;
		struct ip6_net dest6;
	};
	bool is_dest6;
	uint16_t vrf_id;
};

struct gr_srv6_route {
	struct gr_srv6_route_key key;
	gr_srv6_encap_behavior_t encap_behavior;
	uint8_t n_seglist;
	struct rte_ipv6_addr seglist[/* n_seglist */];
};

#define GR_SRV6_ROUTE_ADD REQUEST_TYPE(GR_SRV6_MODULE, 0x0001)

struct gr_srv6_route_add_req {
	uint8_t exist_ok;
	struct gr_srv6_route r;
};

#define GR_SRV6_ROUTE_DEL REQUEST_TYPE(GR_SRV6_MODULE, 0x0002)

struct gr_srv6_route_del_req {
	struct gr_srv6_route_key key;
	uint8_t missing_ok;
};

#define GR_SRV6_ROUTE_LIST REQUEST_TYPE(GR_SRV6_MODULE, 0x0004)

struct gr_srv6_route_list_req {
	uint16_t vrf_id;
};

struct gr_srv6_route_list_resp {
	uint16_t n_route;
	uint8_t route[/* n_route */];
};

// localsid (tunnel transit and exit) /////////////////////////////////

//
// https://www.iana.org/assignments/segment-routing/segment-routing.xhtml
//
// flavor (psp/usd) are defined alongside as flag
//
typedef enum : uint16_t {
	SR_BEHAVIOR_END = 0x0001,
	SR_BEHAVIOR_END_T = 0x0009,
	SR_BEHAVIOR_END_DT6 = 0x0012,
	SR_BEHAVIOR_END_DT4 = 0x0013,
	SR_BEHAVIOR_END_DT46 = 0x0014,

	SR_BEHAVIOR_MAX,
} gr_srv6_behavior_t;

#define GR_SR_FL_FLAVOR_PSP 0x01
#define GR_SR_FL_FLAVOR_USD 0x02
#define GR_SR_FL_FLAVOR_MASK 0x03

struct gr_srv6_localsid {
	struct rte_ipv6_addr lsid;
	uint16_t vrf_id;
	gr_srv6_behavior_t behavior;
	uint8_t flags;
	uint16_t out_vrf_id;
};

#define GR_SRV6_LOCALSID_ADD REQUEST_TYPE(GR_SRV6_MODULE, 0x0021)

struct gr_srv6_localsid_add_req {
	struct gr_srv6_localsid l;
};

#define GR_SRV6_LOCALSID_DEL REQUEST_TYPE(GR_SRV6_MODULE, 0x0022)

struct gr_srv6_localsid_del_req {
	struct rte_ipv6_addr lsid;
	uint16_t vrf_id;
};

#define GR_SRV6_LOCALSID_LIST REQUEST_TYPE(GR_SRV6_MODULE, 0x0023)

struct gr_srv6_localsid_list_req {
	uint16_t vrf_id;
};

struct gr_srv6_localsid_list_resp {
	uint16_t n_lsid;
	struct gr_srv6_localsid lsid[/* n_lsid */];
};
