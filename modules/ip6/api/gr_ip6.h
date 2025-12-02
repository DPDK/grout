// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdint.h>

// IPv6 interface address assignment.
struct gr_ip6_ifaddr {
	uint16_t iface_id;
	struct ip6_net addr;
};

// IPv6 route entry.
struct gr_ip6_route {
	struct ip6_net dest;
	uint16_t vrf_id;
	gr_nh_origin_t origin;
	struct gr_nexthop nh;
};

#define GR_IP6_MODULE 0xfeed

// routes //////////////////////////////////////////////////////////////////////

// Add a new IPv6 route.
#define GR_IP6_ROUTE_ADD REQUEST_TYPE(GR_IP6_MODULE, 0x0010)

struct gr_ip6_route_add_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	struct rte_ipv6_addr nh;
	uint32_t nh_id;
	gr_nh_origin_t origin;
	uint8_t exist_ok;
};

// struct gr_ip6_route_add_resp { };

// Delete an existing IPv6 route.
#define GR_IP6_ROUTE_DEL REQUEST_TYPE(GR_IP6_MODULE, 0x0011)

struct gr_ip6_route_del_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	uint8_t missing_ok;
};

// struct gr_ip6_route_del_resp { };

// Get IPv6 route for a destination address (longest prefix match).
#define GR_IP6_ROUTE_GET REQUEST_TYPE(GR_IP6_MODULE, 0x0012)

struct gr_ip6_route_get_req {
	uint16_t vrf_id;
	struct rte_ipv6_addr dest;
};

struct gr_ip6_route_get_resp {
	struct gr_nexthop nh;
};

// List all IPv6 routes in a VRF.
#define GR_IP6_ROUTE_LIST REQUEST_TYPE(GR_IP6_MODULE, 0x0013)

struct gr_ip6_route_list_req {
	uint16_t vrf_id;
};

STREAM_RESP(struct gr_ip6_route);

// addresses ///////////////////////////////////////////////////////////////////

// Add an IPv6 address to an interface.
#define GR_IP6_ADDR_ADD REQUEST_TYPE(GR_IP6_MODULE, 0x0021)

struct gr_ip6_addr_add_req {
	struct gr_ip6_ifaddr addr;
	uint8_t exist_ok;
};

// struct gr_ip6_addr_add_resp { };

// Delete an IPv6 address from an interface.
#define GR_IP6_ADDR_DEL REQUEST_TYPE(GR_IP6_MODULE, 0x0022)

struct gr_ip6_addr_del_req {
	struct gr_ip6_ifaddr addr;
	uint8_t missing_ok;
};

// struct gr_ip6_addr_del_resp { };

// List IPv6 addresses on interfaces.
#define GR_IP6_ADDR_LIST REQUEST_TYPE(GR_IP6_MODULE, 0x0023)

struct gr_ip6_addr_list_req {
	uint16_t vrf_id;
	uint16_t iface_id;
};

STREAM_RESP(struct gr_ip6_ifaddr);

// router advertisement ////////////////////////////////////////////////////////

// Configure IPv6 router advertisement on an interface.
#define GR_IP6_IFACE_RA_SET REQUEST_TYPE(GR_IP6_MODULE, 0x0030)
struct gr_ip6_ra_set_req {
	uint16_t iface_id;
	uint16_t set_interval : 1;
	uint16_t set_lifetime : 1;

	uint16_t interval; // default 600
	uint16_t lifetime; // default 1800
};
// struct gr_ip6_ra_set_resp { };

// Disable IPv6 router advertisement on an interface.
#define GR_IP6_IFACE_RA_CLEAR REQUEST_TYPE(GR_IP6_MODULE, 0x0031)
struct gr_ip6_ra_clear_req {
	uint16_t iface_id;
};
// struct gr_ip6_ra_clear_resp { };

// Show IPv6 router advertisement configuration.
#define GR_IP6_IFACE_RA_SHOW REQUEST_TYPE(GR_IP6_MODULE, 0x0032)
struct gr_ip6_ra_show_req {
	uint16_t iface_id;
};

// IPv6 router advertisement configuration.
struct gr_ip6_ra_conf {
	bool enabled;
	uint16_t iface_id;
	uint16_t interval;
	uint16_t lifetime;
};

STREAM_RESP(struct gr_ip6_ra_conf);

// icmpv6 //////////////////////////////////////////////////////////////////////

// Send an ICMPv6 echo request (ping6).
#define GR_IP6_ICMP6_SEND REQUEST_TYPE(GR_IP6_MODULE, 0x0041)

struct gr_ip6_icmp_send_req {
	struct rte_ipv6_addr addr;
	uint16_t iface;
	uint16_t vrf;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

// struct gr_ip6_icmp_send_resp { };

// Receive an ICMPv6 echo reply (ping6 response) or error.
#define GR_IP6_ICMP6_RECV REQUEST_TYPE(GR_IP6_MODULE, 0x0042)

struct gr_ip6_icmp_recv_req {
	uint16_t ident;
	uint16_t seq_num;
};

struct gr_ip6_icmp_recv_resp {
	uint8_t type;
	uint8_t code;
	uint8_t ttl;
	uint16_t ident;
	uint16_t seq_num;
	struct rte_ipv6_addr src_addr;
	clock_t response_time;
};

typedef enum {
	GR_EVENT_IP6_ADDR_ADD = EVENT_TYPE(GR_IP6_MODULE, 0x0001),
	GR_EVENT_IP6_ADDR_DEL = EVENT_TYPE(GR_IP6_MODULE, 0x0002),
	GR_EVENT_IP6_ROUTE_ADD = EVENT_TYPE(GR_IP6_MODULE, 0x0003),
	GR_EVENT_IP6_ROUTE_DEL = EVENT_TYPE(GR_IP6_MODULE, 0x0004),
} gr_event_ip6_t;
