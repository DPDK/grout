// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#ifndef _GR_API_SRV6
#define _GR_API_SRV6

#include <gr_api.h>
#include <gr_net_types.h>

#define GR_SRV6_MODULE 0xfeef

//
// SR policy and steering rules are tied together.
//
// for example:
//
//   sr_policy  p1 (bsid=5f00::100, seglist=[5f00::1, 5f00::12], weight=1)
//   sr_policy  p2 (bsid=5f00::101, seglist=[5f00::3], weight=3)
//   steer_rule s1 (match 192.168.0.0/16)
//   steer_rule s2 (match 0.0.0.0/0)
//
// api calls:
//   p1 and p2 are added with GR_SRV6_POLICY_ADD
//   s1 is applied to p1 and p2 (GR_SRV6_STEER_ADD called 2 times
//     with p1.bsid then p2.bsid)
//   s2 applies to p1 only (1 call to GR_SRV6_STEER_ADD)
//
//   if p1 is deleted with GR_SRV6_POLICY_DEL, then s2 is also implicitly deleted
//
// packet processing example:
//   incoming pkt da=192.168.1.1
//     => match steering rule s1
//     => encaps following sr policy p1 (25% traffic) or p2 (75% traffic)
//

// sr policies //////////////////////////////////////////////////////

#define GR_SRV6_POLICY_SEGLIST_COUNT_MAX 60

// SRv6 Policy Headend Behaviors Signaling (rfc8986 8.4)
typedef enum : uint8_t {
	SR_H_ENCAPS,
	SR_H_ENCAPS_RED,

	SR_H_ENCAPS_MAX,
} gr_srv6_encap_behavior_t;

struct gr_srv6_policy {
	struct rte_ipv6_addr bsid;
	uint16_t weight;
	gr_srv6_encap_behavior_t encap_behavior;
	uint8_t n_seglist;
	struct rte_ipv6_addr seglist[/* n_seglist */];
};

#define GR_SRV6_POLICY_ADD REQUEST_TYPE(GR_SRV6_MODULE, 0x0001)

struct gr_srv6_policy_add_req {
	struct gr_srv6_policy p;
};

#define GR_SRV6_POLICY_DEL REQUEST_TYPE(GR_SRV6_MODULE, 0x0002)

struct gr_srv6_policy_del_req {
	struct rte_ipv6_addr bsid;
};

#define GR_SRV6_POLICY_GET REQUEST_TYPE(GR_SRV6_MODULE, 0x0003)

struct gr_srv6_policy_get_req {
	struct rte_ipv6_addr bsid;
};

struct gr_srv6_policy_get_resp {
	struct gr_srv6_policy p;
};

#define GR_SRV6_POLICY_LIST REQUEST_TYPE(GR_SRV6_MODULE, 0x0004)

/* struct gr_srv6_policy_list_req { }; */

struct gr_srv6_policy_list_resp {
	uint16_t n_policy;
	uint8_t policy[/* n_policy */];
};

// headend steering rules (tunnel entry) //////////////////////////////

struct gr_srv6_steer_l3 {
	struct ip4_net dest4;
	struct ip6_net dest6;
	bool is_dest6;
	uint16_t vrf_id;
};

#define GR_SRV6_STEER_ADD REQUEST_TYPE(GR_SRV6_MODULE, 0x0011)

struct gr_srv6_steer_add_req {
	struct rte_ipv6_addr bsid;
	struct gr_srv6_steer_l3 l3;
};

#define GR_SRV6_STEER_DEL REQUEST_TYPE(GR_SRV6_MODULE, 0x0012)

struct gr_srv6_steer_del_req {
	struct rte_ipv6_addr bsid;
	struct gr_srv6_steer_l3 l3;
};

#define GR_SRV6_STEER_LIST REQUEST_TYPE(GR_SRV6_MODULE, 0x0013)

struct gr_srv6_steer_list_req {
	uint16_t vrf_id;
};

struct gr_srv6_steer_entry {
	struct gr_srv6_steer_l3 l3;
	uint16_t n_bsid;
	struct rte_ipv6_addr bsid[/* n_bsid */];
};

struct gr_srv6_steer_list_resp {
	uint16_t n_steer;
	uint8_t steer[/* n_steer */]; // of struct gr_srv6_steer_entry
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

#endif
