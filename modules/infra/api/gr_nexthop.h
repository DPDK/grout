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
#define GR_NH_F_PENDING GR_BIT16(0) // Probe sent
#define GR_NH_F_REACHABLE GR_BIT16(1) // Probe reply received
#define GR_NH_F_STALE GR_BIT16(2) // Reachable lifetime expired, need refresh
#define GR_NH_F_FAILED GR_BIT16(3) // All probes sent without reply
#define GR_NH_F_STATIC GR_BIT16(4) // Configured by user
#define GR_NH_F_LOCAL GR_BIT16(5) // Local address
#define GR_NH_F_GATEWAY GR_BIT16(6) // Gateway route
#define GR_NH_F_LINK GR_BIT16(7) // Connected link route
#define GR_NH_F_MCAST GR_BIT16(8) // Multicast address

typedef uint16_t gr_nh_flags_t;

// Nexthop structure exposed to the API.
struct gr_nexthop {
	gr_nh_flags_t flags; // bit mask of GR_NH_F_*
	union {
		struct {
		} addr;
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
	uint8_t family;
	uint16_t iface_id;
	struct rte_ether_addr mac;
	uint16_t vrf_id;
	uint16_t held_pkts;
	clock_t last_reply;
};

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

#endif
