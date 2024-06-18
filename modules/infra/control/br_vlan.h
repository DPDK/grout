// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_INFRA_VLAN_PRIV
#define _BR_INFRA_VLAN_PRIV

#include <br_iface.h>

#include <rte_ether.h>
#include <rte_mempool.h>

#include <stdint.h>
#include <sys/queue.h>

struct __rte_aligned(alignof(void *)) iface_info_vlan {
	uint16_t parent_id;
	uint16_t vlan_id;
	struct rte_ether_addr mac;
};

struct iface *vlan_get_iface(uint16_t port_id, uint16_t vlan_id);

#endif
