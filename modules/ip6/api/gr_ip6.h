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

enum gr_ip6_requests : uint32_t {
	GR_IP6_ROUTE_ADD = GR_MSG_TYPE(GR_IP6_MODULE, 0x0001),
	GR_IP6_ROUTE_DEL,
	GR_IP6_ROUTE_GET,
	GR_IP6_ROUTE_LIST,
	GR_IP6_ADDR_ADD,
	GR_IP6_ADDR_DEL,
	GR_IP6_ADDR_LIST,
	GR_IP6_ADDR_FLUSH,
	GR_IP6_FIB_DEFAULT_SET,
	GR_IP6_FIB_INFO_LIST,
	GR_IP6_IFACE_RA_SET,
	GR_IP6_IFACE_RA_CLEAR,
	GR_IP6_IFACE_RA_SHOW,
	GR_IP6_ICMP6_SEND,
	GR_IP6_ICMP6_RECV,
};

// routes //////////////////////////////////////////////////////////////////////

// Add a new IPv6 route.
struct gr_ip6_route_add_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	struct rte_ipv6_addr nh;
	uint32_t nh_id;
	gr_nh_origin_t origin;
	uint8_t exist_ok;
};

GR_REQ(GR_IP6_ROUTE_ADD, struct gr_ip6_route_add_req, struct gr_empty);

// Delete an existing IPv6 route.
struct gr_ip6_route_del_req {
	uint16_t vrf_id;
	struct ip6_net dest;
	uint8_t missing_ok;
};

GR_REQ(GR_IP6_ROUTE_DEL, struct gr_ip6_route_del_req, struct gr_empty);

// Get IPv6 route for a destination address (longest prefix match).
struct gr_ip6_route_get_req {
	uint16_t vrf_id;
	struct rte_ipv6_addr dest;
};

struct gr_ip6_route_get_resp {
	struct gr_nexthop nh;
};

GR_REQ(GR_IP6_ROUTE_GET, struct gr_ip6_route_get_req, struct gr_ip6_route_get_resp);

// List all IPv6 routes in a VRF.
struct gr_ip6_route_list_req {
	uint16_t vrf_id;
	uint16_t max_count;
};

GR_REQ_STREAM(GR_IP6_ROUTE_LIST, struct gr_ip6_route_list_req, struct gr_ip6_route);

// addresses ///////////////////////////////////////////////////////////////////

// Add an IPv6 address to an interface.
struct gr_ip6_addr_add_req {
	struct gr_ip6_ifaddr addr;
	uint8_t exist_ok;
};

GR_REQ(GR_IP6_ADDR_ADD, struct gr_ip6_addr_add_req, struct gr_empty);

// Delete an IPv6 address from an interface.
struct gr_ip6_addr_del_req {
	struct gr_ip6_ifaddr addr;
	uint8_t missing_ok;
};

GR_REQ(GR_IP6_ADDR_DEL, struct gr_ip6_addr_del_req, struct gr_empty);

// List IPv6 addresses on interfaces.
struct gr_ip6_addr_list_req {
	uint16_t vrf_id;
	uint16_t iface_id;
};

GR_REQ_STREAM(GR_IP6_ADDR_LIST, struct gr_ip6_addr_list_req, struct gr_ip6_ifaddr);

// Remove all IPv6 addresses from an interface.
struct gr_ip6_addr_flush_req {
	uint16_t iface_id;
};

GR_REQ(GR_IP6_ADDR_FLUSH, struct gr_ip6_addr_flush_req, struct gr_empty);

// fib info ////////////////////////////////////////////////////////////////////

// FIB status for a VRF.
struct gr_fib6_info {
	uint16_t vrf_id;
	uint32_t max_routes; // configured maximum number of routes
	uint32_t used_routes; // number of routes currently installed
	uint32_t num_tbl8; // allocated tbl8 groups (total)
	uint32_t used_tbl8; // tbl8 groups currently in use
};

// Set default FIB configuration for new VRFs.
struct gr_ip6_fib_default_set_req {
	uint32_t max_routes; // 0 = unchanged
};

GR_REQ(GR_IP6_FIB_DEFAULT_SET, struct gr_ip6_fib_default_set_req, struct gr_empty);

// List FIB info for VRFs.
struct gr_ip6_fib_info_list_req {
	uint16_t vrf_id; // GR_VRF_ID_UNDEF for all
};

GR_REQ_STREAM(GR_IP6_FIB_INFO_LIST, struct gr_ip6_fib_info_list_req, struct gr_fib6_info);

// router advertisement ////////////////////////////////////////////////////////

// Configure IPv6 router advertisement on an interface.
struct gr_ip6_ra_set_req {
	uint16_t iface_id;
	uint16_t set_interval : 1;
	uint16_t set_lifetime : 1;

	uint16_t interval; // default 600
	uint16_t lifetime; // default 1800
};

GR_REQ(GR_IP6_IFACE_RA_SET, struct gr_ip6_ra_set_req, struct gr_empty);

// Disable IPv6 router advertisement on an interface.
struct gr_ip6_ra_clear_req {
	uint16_t iface_id;
};

GR_REQ(GR_IP6_IFACE_RA_CLEAR, struct gr_ip6_ra_clear_req, struct gr_empty);

// Show IPv6 router advertisement configuration.
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

GR_REQ_STREAM(GR_IP6_IFACE_RA_SHOW, struct gr_ip6_ra_show_req, struct gr_ip6_ra_conf);

// icmpv6 //////////////////////////////////////////////////////////////////////

// Send an ICMPv6 echo request (ping6).
struct gr_ip6_icmp_send_req {
	struct rte_ipv6_addr addr;
	uint16_t iface;
	uint16_t vrf;
	uint16_t ident;
	uint16_t seq_num;
	uint8_t ttl;
};

GR_REQ(GR_IP6_ICMP6_SEND, struct gr_ip6_icmp_send_req, struct gr_empty);

// Receive an ICMPv6 echo reply (ping6 response) or error.
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

GR_REQ(GR_IP6_ICMP6_RECV, struct gr_ip6_icmp_recv_req, struct gr_ip6_icmp_recv_resp);

// events //////////////////////////////////////////////////////////////////////

enum gr_ip6_events : uint32_t {
	GR_EVENT_IP6_ADDR_ADD = GR_MSG_TYPE(GR_IP6_MODULE, 0x1001),
	GR_EVENT_IP6_ADDR_DEL,
	GR_EVENT_IP6_ROUTE_ADD,
	GR_EVENT_IP6_ROUTE_DEL,
};

GR_EVENT(GR_EVENT_IP6_ADDR_ADD, struct gr_ip6_ifaddr);
GR_EVENT(GR_EVENT_IP6_ADDR_DEL, struct gr_ip6_ifaddr);
GR_EVENT(GR_EVENT_IP6_ROUTE_ADD, struct gr_ip6_route);
GR_EVENT(GR_EVENT_IP6_ROUTE_DEL, struct gr_ip6_route);
