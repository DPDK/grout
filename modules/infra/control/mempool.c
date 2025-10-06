// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_config.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_mempool.h>

#include <stdlib.h>

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
			alloc_size = mempool_default_size;
			if (count > mempool_default_size / 4) {
				alloc_size = count * 2;
				alloc_size = rte_align32pow2(alloc_size) - 1;
				// For future mempools, increase default size;
				mempool_default_size = alloc_size;
			}
			sprintf(mp_name, "mbuf_%d:%d", socket_id, i);
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
					LOG(DEBUG, "free mempool %s", mt->mp->name);
					rte_mempool_free(mp);
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
