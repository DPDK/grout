// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_MSG
#define _GR_IP4_MSG

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdint.h>

struct gr_ip4_ifaddr {
	uint16_t iface_id;
	struct ip4_net addr;
};

struct gr_ip4_route {
	struct ip4_net dest;
	struct gr_nexthop nh;
	gr_nh_origin_t origin;
};

#define GR_IP4_MODULE 0xf00d

// routes //////////////////////////////////////////////////////////////////////

#define GR_IP4_ROUTE_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0010)

struct gr_ip4_route_add_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	ip4_addr_t nh;
	uint32_t nh_id;
	gr_nh_origin_t origin;
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
	struct gr_nexthop nh;
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
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

// struct gr_ip4_icmp_send_resp { };

#define GR_IP4_ICMP_RECV REQUEST_TYPE(GR_IP4_MODULE, 0x0025)

struct gr_ip4_icmp_recv_req {
	uint16_t ident;
	uint16_t seq_num;
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

// events //////////////////////////////////////////////////////////////////////
typedef enum {
	GR_EVENT_IP_ADDR_ADD = EVENT_TYPE(GR_IP4_MODULE, 0x0001),
	GR_EVENT_IP_ADDR_DEL = EVENT_TYPE(GR_IP4_MODULE, 0x0002),
	GR_EVENT_IP_ROUTE_ADD = EVENT_TYPE(GR_IP4_MODULE, 0x0003),
	GR_EVENT_IP_ROUTE_DEL = EVENT_TYPE(GR_IP4_MODULE, 0x0004),
} gr_event_ip_t;

// dnat44 //////////////////////////////////////////////////////////////////////

struct gr_dnat44_rule {
	uint16_t iface_id;
	ip4_addr_t match;
	ip4_addr_t replace;
};

#define GR_DNAT44_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0031)

struct gr_dnat44_add_req {
	struct gr_dnat44_rule rule;
	bool exist_ok;
};

// struct gr_dnat44_add_resp { };

#define GR_DNAT44_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0032)

struct gr_dnat44_del_req {
	struct gr_dnat44_rule rule;
	bool missing_ok;
};

// struct gr_dnat44_del_resp { };

#define GR_DNAT44_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0033)

struct gr_dnat44_list_req {
	uint16_t vrf_id;
};

struct gr_dnat44_list_resp {
	uint16_t n_rules;
	struct gr_dnat44_rule rules[/* n_rules */];
};

#endif
