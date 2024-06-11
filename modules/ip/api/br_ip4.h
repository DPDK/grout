// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_MSG
#define _BR_IP4_MSG

#include <br_api.h>
#include <br_bitops.h>
#include <br_net_types.h>

#include <stdint.h>

struct br_ip4_ifaddr {
	uint16_t iface_id;
	struct ip4_net addr;
};

#define BR_IP4_NH_F_PENDING BR_BIT16(0) // ARP probe sent
#define BR_IP4_NH_F_REACHABLE BR_BIT16(1) // ARP reply received
#define BR_IP4_NH_F_STALE BR_BIT16(2) // Reachable lifetime expired, need ARP refresh
#define BR_IP4_NH_F_FAILED BR_BIT16(3) // All ARP probes sent without reply
#define BR_IP4_NH_F_STATIC BR_BIT16(4) // Configured by user
#define BR_IP4_NH_F_LOCAL BR_BIT16(5) // Local address
#define BR_IP4_NH_F_GATEWAY BR_BIT16(6) // Gateway route
#define BR_IP4_NH_F_LINK BR_BIT16(7) // Connected link route
typedef uint16_t br_ip4_nh_flags_t;

static inline const char *br_ip4_nh_f_name(const br_ip4_nh_flags_t flag) {
	switch (flag) {
	case BR_IP4_NH_F_PENDING:
		return "pending";
	case BR_IP4_NH_F_REACHABLE:
		return "reachable";
	case BR_IP4_NH_F_STALE:
		return "stale";
	case BR_IP4_NH_F_FAILED:
		return "failed";
	case BR_IP4_NH_F_STATIC:
		return "static";
	case BR_IP4_NH_F_LOCAL:
		return "local";
	case BR_IP4_NH_F_GATEWAY:
		return "gateway";
	case BR_IP4_NH_F_LINK:
		return "link";
	}
	return "";
}

#define BR_VRF_ID_ALL UINT16_MAX

struct br_ip4_nh {
	ip4_addr_t host;
	struct eth_addr mac;
	uint16_t vrf_id;
	uint16_t iface_id;
	br_ip4_nh_flags_t flags;
	uint32_t age; //<! number of seconds since last arp reply
	uint16_t held_pkts;
};

struct br_ip4_route {
	struct ip4_net dest;
	ip4_addr_t nh;
};

#define BR_IP4_MODULE 0xf00d

// next hops ///////////////////////////////////////////////////////////////////

#define BR_IP4_NH_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0001)

struct br_ip4_nh_add_req {
	struct br_ip4_nh nh;
	uint8_t exist_ok;
};

// struct br_ip4_nh_add_resp { };

#define BR_IP4_NH_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0002)

struct br_ip4_nh_del_req {
	uint16_t vrf_id;
	ip4_addr_t host;
	uint8_t missing_ok;
};

// struct br_ip4_nh_del_resp { };

#define BR_IP4_NH_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0003)

struct br_ip4_nh_list_req {
	uint16_t vrf_id;
};

struct br_ip4_nh_list_resp {
	uint16_t n_nhs;
	struct br_ip4_nh nhs[/* n_nhs */];
};

// routes //////////////////////////////////////////////////////////////////////

#define BR_IP4_ROUTE_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0010)

struct br_ip4_route_add_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	ip4_addr_t nh;
	uint8_t exist_ok;
};

// struct br_ip4_route_add_resp { };

#define BR_IP4_ROUTE_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0011)

struct br_ip4_route_del_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	uint8_t missing_ok;
};

// struct br_ip4_route_del_resp { };

#define BR_IP4_ROUTE_GET REQUEST_TYPE(BR_IP4_MODULE, 0x0012)

struct br_ip4_route_get_req {
	uint16_t vrf_id;
	ip4_addr_t dest;
};

struct br_ip4_route_get_resp {
	struct br_ip4_nh nh;
};

#define BR_IP4_ROUTE_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0013)

struct br_ip4_route_list_req {
	uint16_t vrf_id;
};

struct br_ip4_route_list_resp {
	uint16_t n_routes;
	struct br_ip4_route routes[/* n_routes */];
};

// addresses ///////////////////////////////////////////////////////////////////

#define BR_IP4_ADDR_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0021)

struct br_ip4_addr_add_req {
	struct br_ip4_ifaddr addr;
	uint8_t exist_ok;
};

// struct br_ip4_addr_add_resp { };

#define BR_IP4_ADDR_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0022)

struct br_ip4_addr_del_req {
	struct br_ip4_ifaddr addr;
	uint8_t missing_ok;
};

// struct br_ip4_addr_del_resp { };

#define BR_IP4_ADDR_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0023)

struct br_ip4_addr_list_req {
	uint16_t vrf_id;
};

struct br_ip4_addr_list_resp {
	uint16_t n_addrs;
	struct br_ip4_ifaddr addrs[/* n_addrs */];
};

#endif
