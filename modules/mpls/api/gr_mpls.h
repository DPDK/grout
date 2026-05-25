// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#pragma once

#include <gr_api.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <stdint.h>

#define GR_MPLS_MODULE 0xf00e

#define GR_MPLS_MAX_LABELS 16

#define GR_MPLS_MAX_STACK_DEPTH 30

#define GR_MPLS_LABEL_MAX 0xFFFFF

// Reserved MPLS label values (RFC 3032).
enum gr_mpls_reserved_labels : uint32_t {
	GR_MPLS_LABEL_IPV4_EXPLICIT_NULL = 0,
	GR_MPLS_LABEL_ROUTER_ALERT = 1,
	GR_MPLS_LABEL_IPV6_EXPLICIT_NULL = 2,
	GR_MPLS_LABEL_IMPLICIT_NULL = 3,
	GR_MPLS_LABEL_FIRST_UNRESERVED = 16,
};

struct gr_nexthop_info_mpls {
	uint8_t n_labels;
	uint8_t ttl; // 0 = copy from payload.
	addr_family_t payload_af; // Payload type after pop (GR_AF_UNSPEC = auto-detect).
	struct l3_addr via;
	uint32_t labels[GR_MPLS_MAX_LABELS];
};

// label routes
enum gr_mpls_requests : uint32_t {
	GR_MPLS_LABEL_ROUTE_ADD = GR_MSG_TYPE(GR_MPLS_MODULE, 0x0001),
	GR_MPLS_LABEL_ROUTE_DEL,
	GR_MPLS_LABEL_ROUTE_GET,
	GR_MPLS_LABEL_ROUTE_LIST,
};

// MPLS label route entry.
struct gr_mpls_label_route {
	uint16_t vrf_id;
	uint32_t in_label;
	uint32_t nh_id;
	gr_nh_origin_t origin;
};

// Add a label route to the LFIB.
struct gr_mpls_label_route_add_req {
	uint16_t vrf_id;
	uint32_t in_label; // 0 to GR_MPLS_LABEL_MAX.
	uint32_t nh_id; // Must reference a GR_NH_T_MPLS nexthop.
	gr_nh_origin_t origin;
	uint8_t exist_ok;
};

GR_REQ(GR_MPLS_LABEL_ROUTE_ADD, struct gr_mpls_label_route_add_req, struct gr_empty);

// Delete a label route from the LFIB.
struct gr_mpls_label_route_del_req {
	uint16_t vrf_id;
	uint32_t in_label;
	uint8_t missing_ok;
};

GR_REQ(GR_MPLS_LABEL_ROUTE_DEL, struct gr_mpls_label_route_del_req, struct gr_empty);

// Get a single label route by label value.
struct gr_mpls_label_route_get_req {
	uint16_t vrf_id;
	uint32_t in_label;
};

GR_REQ(GR_MPLS_LABEL_ROUTE_GET, struct gr_mpls_label_route_get_req, struct gr_mpls_label_route);

// List all label routes in a VRF.
struct gr_mpls_label_route_list_req {
	uint16_t vrf_id;
	uint16_t max_count;
};

GR_REQ_STREAM(
	GR_MPLS_LABEL_ROUTE_LIST,
	struct gr_mpls_label_route_list_req,
	struct gr_mpls_label_route
);

// events

enum gr_mpls_events : uint32_t {
	GR_EVENT_MPLS_ROUTE_ADD = GR_MSG_TYPE(GR_MPLS_MODULE, 0x1001),
	GR_EVENT_MPLS_ROUTE_DEL,
};

GR_EVENT(GR_EVENT_MPLS_ROUTE_ADD, struct gr_mpls_label_route);
GR_EVENT(GR_EVENT_MPLS_ROUTE_DEL, struct gr_mpls_label_route);
