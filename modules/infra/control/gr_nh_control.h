// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_NH_CONTROL
#define _GR_INFRA_NH_CONTROL

#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <event2/event.h>
#include <rte_mbuf.h>

extern struct gr_nexthop_config nh_conf;

int nexthop_config_set(const struct gr_nexthop_config *);
unsigned nexthop_used_count(void);

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

// Compare two nexthops, return True if the same, else False
bool nexthop_equal(const struct nexthop *, const struct nexthop *);

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
