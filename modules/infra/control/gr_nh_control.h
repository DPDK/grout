// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_NH_CONTROL
#define _GR_INFRA_NH_CONTROL

#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <rte_mbuf.h>
#include <rte_spinlock.h>

// Max number of packets to hold per next hop waiting for resolution (default: 256).
#define NH_MAX_HELD_PKTS 256
// Reachable next hop lifetime after last probe reply received (default: 20 min).
#define NH_LIFETIME_REACHABLE (20 * 60)
// Unreachable next hop lifetime after last unreplied probe was sent (default: 1 min).
#define NH_LIFETIME_UNREACHABLE 60
// Max number of unicast probes to send after NH_LIFETIME_REACHABLE.
#define NH_UCAST_PROBES 3
// Max number of multicast/broadcast probes to send after unicast probes failed.
#define NH_BCAST_PROBES 3

struct __rte_cache_aligned nexthop {
	gr_nh_flags_t flags;
	struct rte_ether_addr lladdr;
	uint16_t vrf_id;
	uint16_t iface_id;

	union {
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
	uint8_t prefixlen;

	uint8_t ucast_probes;
	uint8_t bcast_probes;

	uint32_t ref_count; // number of routes referencing this nexthop
	uint64_t last_request;
	uint64_t last_reply;

	// packets waiting for address resolution
	rte_spinlock_t lock;
	uint16_t held_pkts_num;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;
};

#endif
