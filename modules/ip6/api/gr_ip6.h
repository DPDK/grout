// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP6_MSG
#define _GR_IP6_MSG

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdint.h>

struct gr_ip6_ifaddr {
	uint16_t iface_id;
	struct ip6_net addr;
};

struct gr_ip6_route {
	struct ip6_net dest;
	struct rte_ipv6_addr nh;
	uint16_t vrf_id;
};

#define GR_IP6_MODULE 0xfeed

// next hops ///////////////////////////////////////////////////////////////////

#define GR_IP6_NH_ADD REQUEST_TYPE(GR_IP6_MODULE, 0x0001)

struct gr_ip6_nh_add_req {
	struct gr_nexthop nh;
	uint8_t exist_ok;
};

// struct gr_ip6_nh_add_resp { };

#define GR_IP6_NH_DEL REQUEST_TYPE(GR_IP6_MODULE, 0x0002)

struct gr_ip6_nh_del_req {
	uint16_t vrf_id;
	struct rte_ipv6_addr host;
	uint8_t missing_ok;
};

// struct gr_ip6_nh_del_resp { };

#define GR_IP6_NH_LIST REQUEST_TYPE(GR_IP6_MODULE, 0x0003)

struct gr_ip6_nh_list_req {
	uint16_t vrf_id;
};

struct gr_ip6_nh_list_resp {
	uint16_t n_nhs;
	struct gr_nexthop nhs[/* n_nhs */];
};

// routes //////////////////////////////////////////////////////////////////////

#define GR_IP6_ROUTE_ADD REQUEST_TYPE(GR_IP6_MODULE, 0x0010)

struct gr_ip6_route_add_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	struct rte_ipv6_addr nh;
	uint8_t exist_ok;
};

// struct gr_ip6_route_add_resp { };

#define GR_IP6_ROUTE_DEL REQUEST_TYPE(GR_IP6_MODULE, 0x0011)

struct gr_ip6_route_del_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	uint8_t missing_ok;
};

// struct gr_ip6_route_del_resp { };

#define GR_IP6_ROUTE_GET REQUEST_TYPE(GR_IP6_MODULE, 0x0012)

struct gr_ip6_route_get_req {
	uint16_t vrf_id;
	struct rte_ipv6_addr dest;
};

struct gr_ip6_route_get_resp {
	struct gr_nexthop nh;
};

#define GR_IP6_ROUTE_LIST REQUEST_TYPE(GR_IP6_MODULE, 0x0013)

struct gr_ip6_route_list_req {
	uint16_t vrf_id;
};

struct gr_ip6_route_list_resp {
	uint16_t n_routes;
	struct gr_ip6_route routes[/* n_routes */];
};

// addresses ///////////////////////////////////////////////////////////////////

#define GR_IP6_ADDR_ADD REQUEST_TYPE(GR_IP6_MODULE, 0x0021)

struct gr_ip6_addr_add_req {
	struct gr_ip6_ifaddr addr;
	uint8_t exist_ok;
};

// struct gr_ip6_addr_add_resp { };

#define GR_IP6_ADDR_DEL REQUEST_TYPE(GR_IP6_MODULE, 0x0022)

struct gr_ip6_addr_del_req {
	struct gr_ip6_ifaddr addr;
	uint8_t missing_ok;
};

// struct gr_ip6_addr_del_resp { };

#define GR_IP6_ADDR_LIST REQUEST_TYPE(GR_IP6_MODULE, 0x0023)

struct gr_ip6_addr_list_req {
	uint16_t vrf_id;
};

struct gr_ip6_addr_list_resp {
	uint16_t n_addrs;
	struct gr_ip6_ifaddr addrs[/* n_addrs */];
};

#define GR_IP6_IFACE_RA_SET REQUEST_TYPE(GR_IP6_MODULE, 0x0030)
struct gr_ip6_ra_set_req {
	uint16_t iface_id;
};
// struct gr_ip6_ra_set_resp { };

#define GR_IP6_IFACE_RA_CLEAR REQUEST_TYPE(GR_IP6_MODULE, 0x0031)
struct gr_ip6_ra_clear_req {
	uint16_t iface_id;
};
// struct gr_ip6_ra_clear_resp { };
#endif
