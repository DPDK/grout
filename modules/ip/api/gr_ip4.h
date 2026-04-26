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

enum gr_ip4_requests : uint32_t {
	GR_IP4_ROUTE_ADD = GR_MSG_TYPE(GR_IP4_MODULE, 0x0001),
	GR_IP4_ROUTE_DEL,
	GR_IP4_ROUTE_GET,
	GR_IP4_ROUTE_LIST,
	GR_IP4_ADDR_ADD,
	GR_IP4_ADDR_DEL,
	GR_IP4_ADDR_LIST,
	GR_IP4_ADDR_FLUSH,
	GR_IP4_ICMP_SEND,
	GR_IP4_ICMP_RECV,
	GR_IP4_FIB_DEFAULT_SET,
	GR_IP4_FIB_INFO_LIST,
	GR_IP4_ICMP_RATE_LIMIT,
};

// routes //////////////////////////////////////////////////////////////////////

// Add a new IPv4 route.
struct gr_ip4_route_add_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	ip4_addr_t nh;
	uint32_t nh_id;
	gr_nh_origin_t origin;
	uint8_t exist_ok;
};

GR_REQ(GR_IP4_ROUTE_ADD, struct gr_ip4_route_add_req, struct gr_empty);

// Delete an existing IPv4 route.
struct gr_ip4_route_del_req {
	uint16_t vrf_id;
	struct ip4_net dest;
	uint8_t missing_ok;
};

GR_REQ(GR_IP4_ROUTE_DEL, struct gr_ip4_route_del_req, struct gr_empty);

// Get IPv4 route for a destination address (longest prefix match).
struct gr_ip4_route_get_req {
	uint16_t vrf_id;
	ip4_addr_t dest;
};

struct gr_ip4_route_get_resp {
	struct gr_nexthop nh;
};

GR_REQ(GR_IP4_ROUTE_GET, struct gr_ip4_route_get_req, struct gr_ip4_route_get_resp);

// List all IPv4 routes in a VRF.
struct gr_ip4_route_list_req {
	uint16_t vrf_id;
	uint16_t max_count;
};

GR_REQ_STREAM(GR_IP4_ROUTE_LIST, struct gr_ip4_route_list_req, struct gr_ip4_route);

// addresses ///////////////////////////////////////////////////////////////////

// Add an IPv4 address to an interface.
struct gr_ip4_addr_add_req {
	struct gr_ip4_ifaddr addr;
	uint8_t exist_ok;
};

GR_REQ(GR_IP4_ADDR_ADD, struct gr_ip4_addr_add_req, struct gr_empty);

// Delete an IPv4 address from an interface.
struct gr_ip4_addr_del_req {
	struct gr_ip4_ifaddr addr;
	uint8_t missing_ok;
};

GR_REQ(GR_IP4_ADDR_DEL, struct gr_ip4_addr_del_req, struct gr_empty);

// List IPv4 addresses on interfaces.
struct gr_ip4_addr_list_req {
	uint16_t vrf_id;
	uint16_t iface_id;
};

GR_REQ_STREAM(GR_IP4_ADDR_LIST, struct gr_ip4_addr_list_req, struct gr_ip4_ifaddr);

// Remove all IPv4 addresses from an interface.
struct gr_ip4_addr_flush_req {
	uint16_t iface_id;
};

GR_REQ(GR_IP4_ADDR_FLUSH, struct gr_ip4_addr_flush_req, struct gr_empty);

// icmp ////////////////////////////////////////////////////////////////////////

// Send an ICMP echo request (ping).
struct gr_ip4_icmp_send_req {
	ip4_addr_t addr;
	uint16_t vrf;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

GR_REQ(GR_IP4_ICMP_SEND, struct gr_ip4_icmp_send_req, struct gr_empty);

// Receive an ICMP echo reply (ping response) or error.
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

GR_REQ(GR_IP4_ICMP_RECV, struct gr_ip4_icmp_recv_req, struct gr_ip4_icmp_recv_resp);

struct gr_ip4_icmp_rl_req {
	uint32_t rate_limit;
};

GR_REQ(GR_IP4_ICMP_RATE_LIMIT, struct gr_ip4_icmp_rl_req, struct gr_empty);

// fib info ////////////////////////////////////////////////////////////////////

// FIB status for a VRF.
struct gr_fib4_info {
	uint16_t vrf_id;
	uint32_t max_routes; // configured maximum number of routes
	uint32_t used_routes; // number of routes currently installed
	uint32_t num_tbl8; // allocated tbl8 groups (total)
	uint32_t used_tbl8; // tbl8 groups currently in use
};

// Set default FIB configuration for new VRFs.
struct gr_ip4_fib_default_set_req {
	uint32_t max_routes; // 0 = unchanged
};

GR_REQ(GR_IP4_FIB_DEFAULT_SET, struct gr_ip4_fib_default_set_req, struct gr_empty);

// List FIB info for VRFs.
struct gr_ip4_fib_info_list_req {
	uint16_t vrf_id; // GR_VRF_ID_UNDEF for all
};

GR_REQ_STREAM(GR_IP4_FIB_INFO_LIST, struct gr_ip4_fib_info_list_req, struct gr_fib4_info);

// events //////////////////////////////////////////////////////////////////////

// IPv4 module event types.
enum gr_ip4_events : uint32_t {
	GR_EVENT_IP_ADDR_ADD = GR_MSG_TYPE(GR_IP4_MODULE, 0x1001),
	GR_EVENT_IP_ADDR_DEL,
	GR_EVENT_IP_ROUTE_ADD,
	GR_EVENT_IP_ROUTE_DEL,
};

GR_EVENT(GR_EVENT_IP_ADDR_ADD, struct gr_ip4_ifaddr);
GR_EVENT(GR_EVENT_IP_ADDR_DEL, struct gr_ip4_ifaddr);
GR_EVENT(GR_EVENT_IP_ROUTE_ADD, struct gr_ip4_route);
GR_EVENT(GR_EVENT_IP_ROUTE_DEL, struct gr_ip4_route);
