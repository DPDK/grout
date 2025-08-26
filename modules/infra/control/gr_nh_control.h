// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

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

	clock_t last_reply; //!< timestamp when last update was received
	clock_t last_request;

	uint8_t ucast_probes;
	uint8_t bcast_probes;
	uint32_t ref_count; // number of routes referencing this nexthop

	// packets waiting for address resolution
	uint16_t held_pkts;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;

	uint8_t priv[16] __rte_aligned(alignof(void *));
};

#define GR_NH_PRIV_DATA_TYPE(type, fields)                                                         \
	struct type fields __attribute__((__may_alias__, aligned(alignof(void *))));               \
	static inline struct type *type(const struct nexthop *nh) {                                \
		return (struct type *)&nh->priv;                                                   \
	}                                                                                          \
	static_assert(sizeof(struct type) <= MEMBER_SIZE(struct nexthop, priv))

struct hoplist {
	// list managed with gr_vec_*
	struct nexthop **nh;
};

// Lookup a nexthop from the global pool that matches the specified criteria.
struct nexthop *
nexthop_lookup(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr);

// Lookup a nexthop from the global pool from its user provided ID.
struct nexthop *nexthop_lookup_by_id(uint32_t nh_id);

// Compare two nexthops, return True if the same, else False
bool nexthop_equal(const struct nexthop *, const struct nexthop *);

// Allocate a new nexthop from the global pool with the provided initial values.
struct nexthop *nexthop_new(const struct gr_nexthop *);

// Update a nexthop with values from the API.
int nexthop_update(struct nexthop *, const struct gr_nexthop *);

// Clean all next hop related to an interface.
void nexthop_cleanup(uint16_t iface_id);

// Increment the reference counter of a nexthop.
void nexthop_incref(struct nexthop *);

// Decrement the reference counter of a nexthop.
// When the counter drops to 0, the nexthop is marked as available in the global pool.
void nexthop_decref(struct nexthop *);

// Callback for nh_iter().
typedef void (*nh_iter_cb_t)(struct nexthop *nh, void *priv);

// Iterate over all nexthops and invoke a callback for each active nexthop.
void nexthop_iter(nh_iter_cb_t nh_cb, void *priv);

struct nexthop_af_ops {
	// Callback that will be invoked creating a new nexthop.
	int (*add)(struct nexthop *);
	// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
	int (*solicit)(struct nexthop *);
	// Callback that will be invoked when all nexthop probes failed and it needs to be freed.
	void (*del)(struct nexthop *);
};

void nexthop_af_ops_register(addr_family_t af, const struct nexthop_af_ops *);
const struct nexthop_af_ops *nexthop_af_ops_get(addr_family_t af);

struct nexthop_type_ops {
	// Callback that will be invoked the nexthop refcount reaches zero.
	void (*free)(struct nexthop *);
	bool (*equal)(const struct nexthop *, const struct nexthop *);
};

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *);
const struct nexthop_type_ops *nexthop_type_ops_get(gr_nh_type_t type);

// Nexthop statistics structure
struct nh_stats {
	uint32_t total;
	uint32_t by_state[_GR_NH_S_COUNT];
};

// Get nexthop statistics for a given VRF and address family
const struct nh_stats *nexthop_get_stats(uint16_t vrf_id, addr_family_t af);

// Update nexthop stats when state changes
void nh_stats_update(struct nexthop *nh, gr_nh_state_t new_state);
