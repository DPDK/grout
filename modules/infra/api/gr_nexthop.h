// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_NEXTHOP
#define _GR_NEXTHOP

#include <gr_bitops.h>
#include <gr_clock.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

// Supported flags on a nexthop.
typedef enum : uint16_t {
	GR_NH_F_PENDING = GR_BIT16(0), // Probe sent
	GR_NH_F_REACHABLE = GR_BIT16(1), // Probe reply received
	GR_NH_F_STALE = GR_BIT16(2), // Reachable lifetime expired, need refresh
	GR_NH_F_FAILED = GR_BIT16(3), // All probes sent without reply
	GR_NH_F_STATIC = GR_BIT16(4), // Configured by user
	GR_NH_F_LOCAL = GR_BIT16(5), // Local address
	GR_NH_F_GATEWAY = GR_BIT16(6), // Gateway route
	GR_NH_F_LINK = GR_BIT16(7), // Connected link route
	GR_NH_F_MCAST = GR_BIT16(8), // Multicast address
} gr_nh_flags_t;

typedef enum : uint8_t {
	GR_NH_IPV4 = 1,
	GR_NH_IPV6,
	GR_NH_SR6_IPV4,
	GR_NH_SR6_IPV6,
	GR_NH_TYPE_COUNT
} gr_nh_type_t;

//! Nexthop structure exposed to the API.
struct gr_nexthop {
	gr_nh_flags_t flags; //!< bit mask of GR_NH_F_*
	uint16_t vrf_id; //!< L3 VRF domain
	uint16_t iface_id; //!< interface associated with this nexthop
	struct rte_ether_addr mac; //!< link-layer address
	union {
		struct {
		} addr;
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
	gr_nh_type_t type; //!< nexthop type
	uint8_t prefixlen; //!< only has meaning with GR_NH_F_LOCAL
	uint16_t held_pkts; //!< number of packets waiting for resolution
	clock_t last_reply; //!< timestamp when last update was received
};

//! Nexthop events.
typedef enum {
	NEXTHOP_EVENT_NEW = EVENT_TYPE(GR_INFRA_MODULE, 0x0100),
	NEXTHOP_EVENT_DELETE = EVENT_TYPE(GR_INFRA_MODULE, 0x0101),
	NEXTHOP_EVENT_UPDATE = EVENT_TYPE(GR_INFRA_MODULE, 0x0102),
} nexthop_event_t;

#define gr_nh_flags_foreach(f, flags)                                                              \
	for (gr_nh_flags_t __i = 0, f = GR_BIT16(0); __i < sizeof(gr_nh_flags_t) * CHAR_BIT;       \
	     f = GR_BIT16(++__i))                                                                  \
		if (flags & f)

// Return the name of a given flag value.
// When working with flag masks, each individual flags must be iterated upon.
static inline const char *gr_nh_flag_name(const gr_nh_flags_t flag) {
	switch (flag) {
	case GR_NH_F_PENDING:
		return "pending";
	case GR_NH_F_REACHABLE:
		return "reachable";
	case GR_NH_F_STALE:
		return "stale";
	case GR_NH_F_FAILED:
		return "failed";
	case GR_NH_F_STATIC:
		return "static";
	case GR_NH_F_LOCAL:
		return "local";
	case GR_NH_F_GATEWAY:
		return "gateway";
	case GR_NH_F_LINK:
		return "link";
	case GR_NH_F_MCAST:
		return "multicast";
	}
	return "";
}

// Get the address family value from a nexthop.
static inline uint8_t nh_af(const struct gr_nexthop *nh) {
	switch (nh->type) {
	case GR_NH_IPV4:
	case GR_NH_SR6_IPV4:
		return AF_INET;
	case GR_NH_IPV6:
	case GR_NH_SR6_IPV6:
		return AF_INET6;
	case GR_NH_TYPE_COUNT:
		break;
	}
	return 0;
}

struct gr_nexthop_config {
	//! Maximum number of nexthops for all address families (default: 128K).
	uint32_t max_count;
	//! Reachable next hop lifetime after last probe reply received (default: 20 min).
	uint32_t lifetime_reachable_sec;
	//! Unreachable next hop lifetime after last unreplied probe was sent (default: 1 min).
	uint32_t lifetime_unreachable_sec;
	//! Max number of packets to hold per next hop waiting for resolution (default: 256).
	uint16_t max_held_pkts;
	//! Max number of unicast probes to send after NH_LIFETIME_REACHABLE.
	uint8_t max_ucast_probes;
	//! Max number of multicast/broadcast probes to send after unicast probes failed.
	uint8_t max_bcast_probes;
};

#endif
