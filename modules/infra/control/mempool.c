// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "config.h"
#include "log.h"
#include "mbuf.h"
#include "mempool.h"
#include "module.h"
#include "sys_queue.h"

#include <gr_clock.h>

#include <event2/event.h>

#include <stdlib.h>

LOG_TYPE("mempool");

struct pending_free {
	STAILQ_ENTRY(pending_free) next;
	struct rte_mempool *mp;
	gr_clock_ns_t timestamp;
	gr_clock_ns_t last_warn;
};

static STAILQ_HEAD(, pending_free) pending_list = STAILQ_HEAD_INITIALIZER(pending_list);
static struct event *pending_timer;

struct mempool_tracker {
	struct rte_mempool *mp;
	uint32_t reserved;
};

#define MAX_MEMPOOL_PER_NUMA 32
#define MEMPOOL_DEFAULT_SIZE (1 << 16) - 1
#define ETHER_HDR_SIZE 14
#define VLAN_HDR_SIZE 4

static int mt_sort(const void *p1, const void *p2) {
	const struct mempool_tracker *mt1 = p1;
	const struct mempool_tracker *mt2 = p2;

	if (mt1->mp == mt2->mp)
		return 0;

	if (mt1->mp && mt2->mp)
		return (mt2->mp->size - mt2->reserved) - (mt1->mp->size - mt1->reserved);

	return mt1->mp ? -1 : 1;
}

// 1 mempool tracker for each numa + SOCKET_ID_ANY
#define MT_COUNT RTE_MAX_NUMA_NODES + 1
static struct mempool_tracker trackers[MT_COUNT][MAX_MEMPOOL_PER_NUMA];
static uint32_t mempool_default_size = MEMPOOL_DEFAULT_SIZE;
static bool pending_has_name(const char *name);

struct rte_mempool *gr_pktmbuf_pool_get(int8_t socket_id, uint32_t count) {
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp = NULL;
	uint32_t alloc_size;
	uint32_t mbuf_size;

	if (socket_id < SOCKET_ID_ANY || socket_id >= RTE_MAX_NUMA_NODES)
		return errno_set_null(EINVAL);

	mbuf_size = rte_align32pow2(
		RTE_PKTMBUF_HEADROOM + ETHER_HDR_SIZE + VLAN_HDR_SIZE + gr_config.max_mtu
	);

	for (int i = 0; i < MAX_MEMPOOL_PER_NUMA; i++) {
		unsigned mt_index = socket_id == SOCKET_ID_ANY ? 0 : socket_id + 1;
		struct mempool_tracker *mt = &trackers[mt_index][i];
		if (mt->mp == NULL) {
			sprintf(mp_name, "mbuf_%d:%d", socket_id, i);
			if (pending_has_name(mp_name))
				continue;
			alloc_size = mempool_default_size;
			if (count > mempool_default_size / 4) {
				alloc_size = count * 2;
				alloc_size = rte_align32pow2(alloc_size) - 1;
				// For future mempools, increase default size;
				mempool_default_size = alloc_size;
			}
			LOG(DEBUG,
			    "allocate mempool %s reserved %u (size %u, mbuf_size %u)",
			    mp_name,
			    count,
			    alloc_size,
			    mbuf_size);
			mt->mp = rte_pktmbuf_pool_create(
				mp_name,
				alloc_size,
				RTE_MEMPOOL_CACHE_MAX_SIZE,
				GR_MBUF_PRIV_MAX_SIZE,
				mbuf_size,
				socket_id
			);
			if (mt->mp == NULL)
				return errno_set_null(rte_errno);
			mt->reserved = count;
			mp = mt->mp;
			break;
		} else if ((count + mt->reserved) <= mt->mp->size) {
			LOG(DEBUG,
			    "reuse mempool %s reserved %u -> %u (size %u, mbuf_size %u)",
			    mt->mp->name,
			    mt->reserved,
			    mt->reserved + count,
			    mt->mp->size,
			    mbuf_size);
			mt->reserved += count;
			mp = mt->mp;
			break;
		}
	}

	for (int s = 0; s < MT_COUNT; s++) {
		struct mempool_tracker *mt = trackers[s];
		qsort(mt, MAX_MEMPOOL_PER_NUMA, sizeof(*mt), mt_sort);
	}

	return mp;
}

#define PENDING_WARN_INTERVAL (5 * 60 * GR_NS_PER_S)

static bool pending_has_name(const char *name) {
	struct pending_free *pf;

	STAILQ_FOREACH (pf, &pending_list, next) {
		if (strcmp(pf->mp->name, name) == 0)
			return true;
	}
	return false;
}

static void pending_free_cb(evutil_socket_t, short, void *) {
	struct pending_free *pf, *tmp;
	gr_clock_ns_t now = gr_clock_ns();

	STAILQ_FOREACH_SAFE (pf, &pending_list, next, tmp) {
		gr_clock_ns_t elapsed = now - pf->timestamp;
		if (rte_mempool_full(pf->mp)) {
			LOG(DEBUG,
			    "deferred free mempool %s after %lu ms",
			    pf->mp->name,
			    (elapsed * 1000) / GR_NS_PER_S);
			rte_mempool_free(pf->mp);
			STAILQ_REMOVE(&pending_list, pf, pending_free, next);
			free(pf);
		} else if (elapsed > pf->last_warn + PENDING_WARN_INTERVAL) {
			pf->last_warn = elapsed;
			LOG(WARNING,
			    "mempool %s still not empty after %lu s",
			    pf->mp->name,
			    elapsed / GR_NS_PER_S);
		}
	}
}

void gr_pktmbuf_pool_release(struct rte_mempool *mp, uint32_t count) {
	if (mp == NULL)
		return;

	for (int s = 0; s < MT_COUNT; s++)
		for (int i = 0; i < MAX_MEMPOOL_PER_NUMA; i++) {
			struct mempool_tracker *mt = &trackers[s][i];
			if (mt->mp == mp) {
				assert(mt->reserved >= count);
				LOG(DEBUG,
				    "release mempool %s reserved %u -> %u (size %u)",
				    mt->mp->name,
				    mt->reserved,
				    mt->reserved - count,
				    mt->mp->size);
				mt->reserved -= count;
				if (mt->reserved == 0) {
					struct pending_free *pf = malloc(sizeof(*pf));
					if (pf == NULL)
						ABORT("malloc(pending_free) failed");
					pf->mp = mp;
					pf->timestamp = gr_clock_ns();
					pf->last_warn = 0;
					STAILQ_INSERT_TAIL(&pending_list, pf, next);
					LOG(DEBUG,
					    "schedule mempool %s for deferred free",
					    mp->name);
					mt->mp = NULL;
					mt->reserved = 0;
				}
				break;
			}
		}

	for (int s = 0; s < MT_COUNT; s++) {
		struct mempool_tracker *mt = trackers[s];
		qsort(mt, MAX_MEMPOOL_PER_NUMA, sizeof(*mt), mt_sort);
	}
}

static void mempool_init(struct event_base *ev_base) {
	pending_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, pending_free_cb, NULL);
	if (pending_timer == NULL)
		ABORT("event_new() failed");
	if (event_add(pending_timer, &(struct timeval) {.tv_sec = 1}) < 0)
		ABORT("event_add() failed");
}

static void mempool_fini(struct event_base *) {
	struct pending_free *pf;

	if (pending_timer)
		event_free(pending_timer);

	while ((pf = STAILQ_FIRST(&pending_list)) != NULL) {
		if (rte_mempool_full(pf->mp))
			LOG(DEBUG, "freeing pending mempool %s", pf->mp->name);
		else
			LOG(ERR,
			    "freeing mempool %s with mbufs still in-flight (released %lu s ago)",
			    pf->mp->name,
			    (gr_clock_ns() - pf->timestamp) / GR_NS_PER_S);
		rte_mempool_free(pf->mp);
		STAILQ_REMOVE_HEAD(&pending_list, next);
		free(pf);
	}
}

static struct module mempool_module = {
	.name = "mempool",
	.init = mempool_init,
	.fini = mempool_fini,
};

RTE_INIT(mempool_module_init) {
	module_register(&mempool_module);
}
