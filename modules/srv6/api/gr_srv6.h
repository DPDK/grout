// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#define GR_SRV6_MODULE 0xfeef

// sr routes //////////////////////////////////////////////////////

#define GR_SRV6_ROUTE_SEGLIST_COUNT_MAX 60

// SRv6 Route Headend Behaviors Signaling (rfc8986 8.4)
typedef enum : uint8_t {
	SR_H_ENCAPS,
	SR_H_ENCAPS_RED,
} gr_srv6_encap_behavior_t;

struct gr_nexthop_info_srv6 {
	gr_srv6_encap_behavior_t encap_behavior;
	uint8_t n_seglist;
	struct rte_ipv6_addr seglist[];
};

// sr tun src //////////////////////////////////////////////////////

#define GR_SRV6_TUNSRC_SET REQUEST_TYPE(GR_SRV6_MODULE, 0x0005)
struct gr_srv6_tunsrc_set_req {
	struct rte_ipv6_addr addr;
};

#define GR_SRV6_TUNSRC_CLEAR REQUEST_TYPE(GR_SRV6_MODULE, 0x0006)
// struct gr_srv6_tunsrc_clear_req { };

#define GR_SRV6_TUNSRC_SHOW REQUEST_TYPE(GR_SRV6_MODULE, 0x0007)
// struct gr_srv6_tunsrc_show_req { };

struct gr_srv6_tunsrc_show_resp {
	struct rte_ipv6_addr addr;
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
} gr_srv6_behavior_t;

static inline const char *gr_srv6_behavior_name(gr_srv6_behavior_t b) {
	switch (b) {
	case SR_BEHAVIOR_END:
		return "end";
	case SR_BEHAVIOR_END_T:
		return "end.t";
	case SR_BEHAVIOR_END_DT6:
		return "end.dt6";
	case SR_BEHAVIOR_END_DT4:
		return "end.dt4";
	case SR_BEHAVIOR_END_DT46:
		return "end.dt46";
	}
	return "?";
}

typedef enum : uint8_t {
	GR_SR_FL_FLAVOR_PSP = GR_BIT8(0),
	GR_SR_FL_FLAVOR_USD = GR_BIT8(1),
} gr_srv6_flags_t;

struct gr_nexthop_info_srv6_local {
	uint16_t out_vrf_id;
	gr_srv6_behavior_t behavior;
	gr_srv6_flags_t flags;
};
