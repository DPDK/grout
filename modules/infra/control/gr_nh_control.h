// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_INFRA_NH_CONTROL
#define _GR_INFRA_NH_CONTROL

#include <gr_net_types.h>
#include <gr_nexthop.h>

#include <event2/event.h>
#include <rte_mbuf.h>

// Forward declaration
struct nexthop;

// Nexthop pool. Only one should be needed per L3 address family.
struct nh_pool;

// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
typedef int (*nh_solicit_cb_t)(struct nexthop *);

// Callback that will be invoked when all nexthop probes failed and it needs to be freed.
typedef void (*nh_free_cb_t)(struct nexthop *);

// Nexthop pool options.
struct nh_pool_opts {
	// Callback that will be invoked when a nexthop needs to be refreshed by sending a probe.
	nh_solicit_cb_t solicit_nh;
	// Callback that will be invoked when all nexthop probes failed and it needs to be freed.
	nh_free_cb_t free_nh;
	// The number of nexthops allocated in this pool.
	unsigned num_nexthops;
};

// Allocate a new nexthop pool with the provided options.
// If any field left to 0 in opts the default values will be used.
struct nh_pool *
nh_pool_new(uint8_t family, struct event_base *base, const struct nh_pool_opts *opts);

// Free a nexthop pool previously allocated with nh_pool_new().
void nh_pool_free(struct nh_pool *);

// nh_pool_iter callback.
typedef void (*nh_iter_cb_t)(struct nexthop *nh, void *priv);

// Iterate over a nexthop pool and invoke a callback for each active nexthop.
void nh_pool_iter(struct nh_pool *, nh_iter_cb_t nh_cb, void *priv);

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
		struct {
		} addr;
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
	uint8_t prefixlen;
	uint8_t family; // AF_INET, AF_INET6, ...

	uint8_t ucast_probes;
	uint8_t bcast_probes;
	uint32_t ref_count; // number of routes referencing this nexthop
	uint64_t last_request;
	uint64_t last_reply;

	// packets waiting for address resolution
	uint16_t held_pkts_num;
	struct rte_mbuf *held_pkts_head;
	struct rte_mbuf *held_pkts_tail;

	// internal
	struct nh_pool *pool;
};

struct hoplist {
	// list managed with gr_vec_*
	struct nexthop **nh;
};

struct nexthop *
nexthop_lookup(struct nh_pool *, uint16_t vrf_id, uint16_t iface_id, const void *addr);
struct nexthop *nexthop_new(struct nh_pool *, uint16_t vrf_id, uint16_t iface_id, const void *addr);

void nexthop_incref(struct nexthop *);
void nexthop_decref(struct nexthop *);

void nexthop_push_notification(nexthop_event_t, struct nexthop *);

#endif
