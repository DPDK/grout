// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdint.h>

// IPv4 interface address assignment.
struct gr_ip4_ifaddr {
	uint16_t iface_id;
	struct ip4_net addr;
};

// IPv4 route entry.
struct gr_ip4_route {
	struct ip4_net dest;
	uint16_t vrf_id;
	gr_nh_origin_t origin;
	struct gr_nexthop nh;
};

#define GR_IP4_MODULE 0xf00d

// routes //////////////////////////////////////////////////////////////////////

// Add a new IPv4 route.
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

// Delete an existing IPv4 route.
#define GR_IP4_ROUTE_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0011)

struct gr_ip4_route_del_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	uint8_t missing_ok;
};

// struct gr_ip4_route_del_resp { };

// Get IPv4 route for a destination address (longest prefix match).
#define GR_IP4_ROUTE_GET REQUEST_TYPE(GR_IP4_MODULE, 0x0012)

struct gr_ip4_route_get_req {
	uint16_t vrf_id;
	ip4_addr_t dest;
};

struct gr_ip4_route_get_resp {
	struct gr_nexthop nh;
};

// List all IPv4 routes in a VRF.
#define GR_IP4_ROUTE_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0013)

struct gr_ip4_route_list_req {
	uint16_t vrf_id;
};

STREAM_RESP(struct gr_ip4_route);

// addresses ///////////////////////////////////////////////////////////////////

// Add an IPv4 address to an interface.
#define GR_IP4_ADDR_ADD REQUEST_TYPE(GR_IP4_MODULE, 0x0021)

struct gr_ip4_addr_add_req {
	struct gr_ip4_ifaddr addr;
	uint8_t exist_ok;
};

// struct gr_ip4_addr_add_resp { };

// Delete an IPv4 address from an interface.
#define GR_IP4_ADDR_DEL REQUEST_TYPE(GR_IP4_MODULE, 0x0022)

struct gr_ip4_addr_del_req {
	struct gr_ip4_ifaddr addr;
	uint8_t missing_ok;
};

// struct gr_ip4_addr_del_resp { };

// List IPv4 addresses on interfaces.
#define GR_IP4_ADDR_LIST REQUEST_TYPE(GR_IP4_MODULE, 0x0023)

struct gr_ip4_addr_list_req {
	uint16_t vrf_id;
	uint16_t iface_id;
};

STREAM_RESP(struct gr_ip4_ifaddr);

// Remove all IPv4 addresses from an interface.
#define GR_IP4_ADDR_FLUSH REQUEST_TYPE(GR_IP4_MODULE, 0x0026)

struct gr_ip4_addr_flush_req {
	uint16_t iface_id;
};

// struct gr_ip4_addr_flush_resp { };

// icmp ////////////////////////////////////////////////////////////////////////

// Send an ICMP echo request (ping).
#define GR_IP4_ICMP_SEND REQUEST_TYPE(GR_IP4_MODULE, 0x0024)

struct gr_ip4_icmp_send_req {
	ip4_addr_t addr;
	uint16_t vrf;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

// struct gr_ip4_icmp_send_resp { };

// Receive an ICMP echo reply (ping response) or error.
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

// IPv4 module event types.
typedef enum {
	GR_EVENT_IP_ADDR_ADD = EVENT_TYPE(GR_IP4_MODULE, 0x0001),
	GR_EVENT_IP_ADDR_DEL = EVENT_TYPE(GR_IP4_MODULE, 0x0002),
	GR_EVENT_IP_ROUTE_ADD = EVENT_TYPE(GR_IP4_MODULE, 0x0003),
	GR_EVENT_IP_ROUTE_DEL = EVENT_TYPE(GR_IP4_MODULE, 0x0004),
} gr_event_ip_t;
