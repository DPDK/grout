// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_API_SRV6
#define _GR_API_SRV6

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

//
// https://www.iana.org/assignments/segment-routing/segment-routing.xhtml
//
enum gr_srv6_behavior {
	SR_BEHAVIOR_END = 0x0001,
	SR_BEHAVIOR_END_T = 0x0009,
	SR_BEHAVIOR_END_DT6 = 0x0012,
	SR_BEHAVIOR_END_DT4 = 0x0013,
	SR_BEHAVIOR_END_DT46 = 0x0014,

	SR_BEHAVIOR_MAX,
};

#define GR_SRV6_MODULE 0xfeef

// steer ///////////////////////////////////////////////////////////////////

struct gr_srv6_steer {
	struct ip4_net dest4;
	struct ip6_net dest6;
	bool is_dest6;
	uint16_t vrf_id;
	uint16_t n_nh;
	struct rte_ipv6_addr nh[/* n_nh */];
};

#define GR_SRV6_STEER_ADD REQUEST_TYPE(GR_SRV6_MODULE, 0x0011)

struct gr_srv6_steer_add_req {
	struct gr_srv6_steer s;
};

#define GR_SRV6_STEER_DEL REQUEST_TYPE(GR_SRV6_MODULE, 0x0012)

struct gr_srv6_steer_del_req {
	struct gr_srv6_steer s;
};

#define GR_SRV6_STEER_LIST REQUEST_TYPE(GR_SRV6_MODULE, 0x0013)

struct gr_srv6_steer_list_req {
	uint16_t vrf_id;
};

struct gr_srv6_steer_list_resp {
	uint16_t n_steer;
	uint8_t steer[/* n_steer */];
};

// localsid ///////////////////////////////////////////////////////////////////

struct gr_srv6_localsid {
	struct rte_ipv6_addr lsid;
	uint16_t vrf_id;
	enum gr_srv6_behavior behavior;
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

#endif
