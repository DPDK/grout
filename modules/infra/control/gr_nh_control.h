// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_macro.h>
#include <gr_net_types.h>
#include <gr_nexthop.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_mbuf.h>

#include <assert.h>
#include <stdalign.h>

extern struct gr_nexthop_config nh_conf;

int nexthop_config_set(const struct gr_nexthop_config *);
unsigned nexthop_used_count(void);

struct __rte_cache_aligned nexthop {
	BASE(gr_nexthop_base);

	uint32_t ref_count; // number of routes referencing this nexthop

	uint8_t info
		[RTE_CACHE_LINE_MIN_SIZE * 2 - sizeof(struct gr_nexthop_base)
		 - sizeof(uint32_t)] __rte_aligned(alignof(void *));
};
static_assert(sizeof(struct nexthop) <= (RTE_CACHE_LINE_MIN_SIZE * 2));

#define GR_NH_TYPE_INFO(type_id, type_name, fields)                                                \
	struct type_name fields __attribute__((__may_alias__, aligned(alignof(void *))));          \
	static inline struct type_name *type_name(const struct nexthop *nh) {                      \
		assert(nh->type == type_id);                                                       \
		return (struct type_name *)&nh->info;                                              \
	}                                                                                          \
	static_assert(sizeof(struct type_name) <= MEMBER_SIZE(struct nexthop, info))

GR_NH_TYPE_INFO(GR_NH_T_L3, nexthop_info_l3, {
	BASE(gr_nexthop_info_l3);

	clock_t last_reply; //!< timestamp when last update was received
	clock_t last_request;

	uint8_t ucast_probes;
	uint8_t bcast_probes;

	// packets waiting for address resolution
	uint16_t held_pkts;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;
});

struct hoplist {
	gr_vec struct nexthop **nh;
};

struct nh_group_member {
	struct nexthop *nh;
	uint32_t weight;
};

#define MAX_NH_GROUP_RETA_SIZE 4096
GR_NH_TYPE_INFO(GR_NH_T_GROUP, nexthop_info_group, {
	uint16_t n_members;
	uint16_t reta_size; // MUST BE A POWER OF TWO
	struct nh_group_member *members;
	struct nexthop **reta;
});

static inline struct nexthop *
nexthop_group_get_nh(struct nexthop_info_group *nhg, uint32_t flow_id) {
	if (unlikely(nhg->n_members == 0))
		return NULL;
	return nhg->reta[flow_id & (nhg->reta_size - 1)];
}

// Lookup an L3 nexthop that matches the specified criteria.
struct nexthop *
nexthop_lookup_l3(addr_family_t af, uint16_t vrf_id, uint16_t iface_id, const void *addr);

// Lookup a nexthop from its user provided ID.
struct nexthop *nexthop_lookup_id(uint32_t nh_id);

// Compare two nexthops, return True if the same, else False
bool nexthop_equal(const struct nexthop *, const struct nexthop *);

// Check if a nexthop type value is valid.
bool nexthop_type_valid(gr_nh_type_t);

// Check if an origin value is valid.
bool nexthop_origin_valid(gr_nh_origin_t);

// Allocate a new nexthop from the global pool with the provided initial values.
struct nexthop *nexthop_new(const struct gr_nexthop_base *, const void *info);

// Update a nexthop with values from the API.
int nexthop_update(struct nexthop *, const struct gr_nexthop_base *, const void *info);

// Convert a nexthop to its public representation in the API.
// The returned value must be deallocated with free().
struct gr_nexthop *nexthop_to_api(const struct nexthop *, size_t *len);

// Uses nexthop_export to serve as callback for gr_event_serializer.
int nexthop_serialize(const void *obj, void **buf);

// Clean all routes that reference a given nexthop.
void nexthop_routes_cleanup(struct nexthop *);

// Increment the reference counter of a nexthop.
void nexthop_incref(struct nexthop *);

// Decrement the reference counter of a nexthop.
// When the counter drops to 0, the nexthop is destroyed and returned to the global pool.
void nexthop_decref(struct nexthop *);

// Return the nexthop to the global pool regardless of its refcount.
void nexthop_destroy(struct nexthop *);

// Callback for nh_iter().
typedef void (*nh_iter_cb_t)(struct nexthop *nh, void *priv);

// Iterate over all nexthops and invoke a callback for each active nexthop.
void nexthop_iter(nh_iter_cb_t nh_cb, void *priv);

struct nexthop_af_ops {
	// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
	int (*solicit)(struct nexthop *);
	// Callback that will be invoked to delete all routes which reference a given nexthop.
	void (*cleanup_routes)(struct nexthop *);
};

void nexthop_af_ops_register(addr_family_t af, const struct nexthop_af_ops *);

struct nexthop_type_ops {
	int (*reconfig)(const struct gr_nexthop_config *);
	// Callback that will be invoked the nexthop refcount reaches zero.
	void (*free)(struct nexthop *);
	bool (*equal)(const struct nexthop *, const struct nexthop *);
	// Copy public info structure to internal info structure.
	int (*import_info)(struct nexthop *, const void *public_info);
	// Convert a nexthop to its public representation in the API (including the base fields).
	struct gr_nexthop *(*to_api)(const struct nexthop *, size_t *len);
};

void nexthop_type_ops_register(gr_nh_type_t type, const struct nexthop_type_ops *);

// Local IP address nexthops will have these flags set.
#define NH_LOCAL_ADDR_FLAGS (GR_NH_F_LOCAL | GR_NH_F_LINK | GR_NH_F_STATIC)
