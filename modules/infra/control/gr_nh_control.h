// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_NH_CONTROL
#define _GR_INFRA_NH_CONTROL

#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <event2/event.h>
#include <rte_mbuf.h>

//! Max number of packets to hold per next hop waiting for resolution (default: 256).
#define NH_MAX_HELD_PKTS 256
//! Reachable next hop lifetime after last probe reply received (default: 20 min).
#define NH_LIFETIME_REACHABLE (20 * 60)
//! Unreachable next hop lifetime after last unreplied probe was sent (default: 1 min).
#define NH_LIFETIME_UNREACHABLE 60
//! Max number of unicast probes to send after NH_LIFETIME_REACHABLE.
#define NH_UCAST_PROBES 3
//! Max number of multicast/broadcast probes to send after unicast probes failed.
#define NH_BCAST_PROBES 3
//! Maximum number of nexthops (TODO: make this configurable)
#define NH_MAX_COUNT (1 << 17)

struct __rte_cache_aligned nexthop {
	BASE(gr_nexthop);

	clock_t last_request;

	uint8_t ucast_probes;
	uint8_t bcast_probes;
	uint32_t ref_count; // number of routes referencing this nexthop

	// packets waiting for address resolution
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;
};

struct hoplist {
	// list managed with gr_vec_*
	struct nexthop **nh;
};

// Lookup a nexthop from the global pool that matches the specified criteria.
struct nexthop *
nexthop_lookup(gr_nh_type_t type, uint16_t vrf_id, uint16_t iface_id, const void *addr);

// Allocate a new nexthop from the global pool with the provided initial values.
struct nexthop *
nexthop_new(gr_nh_type_t type, uint16_t vrf_id, uint16_t iface_id, const void *addr);

// Increment the reference counter of a nexthop.
void nexthop_incref(struct nexthop *);

// Decrement the reference counter of a nexthop.
// When the counter drops to 0, the nexthop is marked as available in the global pool.
void nexthop_decref(struct nexthop *);

// Callback for nh_iter().
typedef void (*nh_iter_cb_t)(struct nexthop *nh, void *priv);

// Iterate over all nexthops and invoke a callback for each active nexthop.
void nexthop_iter(nh_iter_cb_t nh_cb, void *priv);

struct nexthop_ops {
	// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
	int (*solicit)(struct nexthop *);
	// Callback that will be invoked when all nexthop probes failed and it needs to be freed.
	void (*free)(struct nexthop *);
};

void nexthop_ops_register(gr_nh_type_t type, const struct nexthop_ops *);

#endif
