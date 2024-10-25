// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_MSG
#define _GR_IP4_MSG

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>

#include <stdint.h>

struct gr_ip4_ifaddr {
	uint16_t iface_id;
	struct ip4_net addr;
};

#define GR_IP4_NH_F_PENDING GR_BIT16(0) // ARP probe sent
#define GR_IP4_NH_F_REACHABLE GR_BIT16(1) // ARP reply received
#define GR_IP4_NH_F_STALE GR_BIT16(2) // Reachable lifetime expired, need ARP refresh
#define GR_IP4_NH_F_FAILED GR_BIT16(3) // All ARP probes sent without reply
#define GR_IP4_NH_F_STATIC GR_BIT16(4) // Configured by user
#define GR_IP4_NH_F_LOCAL GR_BIT16(5) // Local address
#define GR_IP4_NH_F_GATEWAY GR_BIT16(6) // Gateway route
#define GR_IP4_NH_F_LINK GR_BIT16(7) // Connected link route
typedef uint16_t gr_ip4_nh_flags_t;

static inline const char *gr_ip4_nh_f_name(const gr_ip4_nh_flags_t flag) {
	switch (flag) {
	case GR_IP4_NH_F_PENDING:
		return "pending";
	case GR_IP4_NH_F_REACHABLE:
		return "reachable";
	case GR_IP4_NH_F_STALE:
		return "stale";
	case GR_IP4_NH_F_FAILED:
		return "failed";
	case GR_IP4_NH_F_STATIC:
		return "static";
	case GR_IP4_NH_F_LOCAL:
		return "local";
	case GR_IP4_NH_F_GATEWAY:
		return "gateway";
	case GR_IP4_NH_F_LINK:
		return "link";
	}
	return "";
}

#define GR_VRF_ID_ALL UINT16_MAX

struct gr_ip4_nh {
	ip4_addr_t host;
	struct rte_ether_addr mac;
	uint16_t vrf_id;
	uint16_t iface_id;
	gr_ip4_nh_flags_t flags;
	uint16_t age; //<! number of seconds since last update
	uint16_t held_pkts;
};

struct gr_ip4_route {
	struct ip4_net dest;
	ip4_addr_t nh;
	uint16_t vrf_id;
};

#define GR_IP4_MODULE 0xf00d

// next hops ///////////////////////////////////////////////////////////////////

#define GR_IP4_NH_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0001)

struct gr_ip4_nh_add_req {
	struct gr_ip4_nh nh;
	uint8_t exist_ok;
};

// struct gr_ip4_nh_add_resp { };

#define GR_IP4_NH_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0002)

struct gr_ip4_nh_del_req {
	uint16_t vrf_id;
	ip4_addr_t host;
	uint8_t missing_ok;
};

// struct gr_ip4_nh_del_resp { };

#define GR_IP4_NH_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0003)

struct gr_ip4_nh_list_req {
	uint16_t vrf_id;
};

struct gr_ip4_nh_list_resp {
	uint16_t n_nhs;
	struct gr_ip4_nh nhs[/* n_nhs */];
};

// routes //////////////////////////////////////////////////////////////////////

#define GR_IP4_ROUTE_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0010)

struct gr_ip4_route_add_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	ip4_addr_t nh;
	uint8_t exist_ok;
};

// struct gr_ip4_route_add_resp { };

#define GR_IP4_ROUTE_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0011)

struct gr_ip4_route_del_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	uint8_t missing_ok;
};

// struct gr_ip4_route_del_resp { };

#define GR_IP4_ROUTE_GET REQUEST_TYPE(GR_IP4_MODULE, 0x0012)

struct gr_ip4_route_get_req {
	uint16_t vrf_id;
	ip4_addr_t dest;
};

struct gr_ip4_route_get_resp {
	struct gr_ip4_nh nh;
};

#define GR_IP4_ROUTE_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0013)

struct gr_ip4_route_list_req {
	uint16_t vrf_id;
};

struct gr_ip4_route_list_resp {
	uint16_t n_routes;
	struct gr_ip4_route routes[/* n_routes */];
};

// addresses ///////////////////////////////////////////////////////////////////

#define GR_IP4_ADDR_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0021)

struct gr_ip4_addr_add_req {
	struct gr_ip4_ifaddr addr;
	uint8_t exist_ok;
};

// struct gr_ip4_addr_add_resp { };

#define GR_IP4_ADDR_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0022)

struct gr_ip4_addr_del_req {
	struct gr_ip4_ifaddr addr;
	uint8_t missing_ok;
};

// struct gr_ip4_addr_del_resp { };

#define GR_IP4_ADDR_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0023)

struct gr_ip4_addr_list_req {
	uint16_t vrf_id;
};

struct gr_ip4_addr_list_resp {
	uint16_t n_addrs;
	struct gr_ip4_ifaddr addrs[/* n_addrs */];
};

// icmp ////////////////////////////////////////////////////////////////////////

#define GR_IP4_ICMP_SEND REQUEST_TYPE(GR_IP4_MODULE, 0x0024)

struct gr_ip4_icmp_send_req {
	ip4_addr_t addr;
	uint16_t vrf;
	uint16_t seq_num;
	uint8_t ttl;
};

struct gr_ip4_icmp_send_resp {
	uint16_t id;
};

#define GR_IP4_ICMP_RECV REQUEST_TYPE(GR_IP4_MODULE, 0x0025)

struct gr_ip4_icmp_recv_req {
	uint16_t id;
};

struct gr_ip4_icmp_recv_resp {
	uint8_t type;
	uint8_t code;
	uint8_t ttl;
	uint16_t ident;
	uint16_t seq_num;
	ip4_addr_t src_addr;
	clock_t response_time;
};

#endif
