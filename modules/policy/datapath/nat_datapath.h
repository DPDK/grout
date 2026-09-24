// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include "checksum.h"
#include "iface.h"
#include "nexthop.h"

#include <gr_nat.h>
#include <gr_net_types.h>

#include <rte_ip.h>

GR_NH_TYPE_INFO(GR_NH_T_DNAT, nexthop_info_dnat, {
	BASE(gr_nexthop_info_dnat);
	struct nexthop *arp;
});

typedef enum {
	NAT_VERDICT_CONTINUE,
	NAT_VERDICT_FINAL,
	NAT_VERDICT_DROP,
} nat_verdict_t;

nat_verdict_t snat44_static_process(const struct iface *, struct rte_mbuf *);
nat_verdict_t snat44_dynamic_process(const struct iface *, struct rte_mbuf *);

static inline nat_verdict_t snat44_process(const struct iface *iface, struct rte_mbuf *mbuf) {
	nat_verdict_t verdict = NAT_VERDICT_CONTINUE;

	if (iface->flags & GR_IFACE_F_SNAT_STATIC)
		verdict = snat44_static_process(iface, mbuf);

	if (verdict == NAT_VERDICT_CONTINUE && iface->flags & GR_IFACE_F_SNAT_DYNAMIC)
		verdict = snat44_dynamic_process(iface, mbuf);

	return verdict;
}
