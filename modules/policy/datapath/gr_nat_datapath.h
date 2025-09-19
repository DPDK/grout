// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_nat.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ip.h>

GR_NH_TYPE_INFO(GR_NH_T_DNAT, nexthop_info_dnat, {
	BASE(gr_nexthop_info_dnat);
	struct nexthop *arp;
});

static inline rte_be16_t
fixup_checksum_16(rte_be16_t old_cksum, rte_be16_t old_field, rte_be16_t new_field) {
	uint32_t sum;

	// RFC 1624: HC' = ~(~HC + ~m + m')
	// Note: 1's complement sum is endian-independent (RFC 1071, page 2).
	sum = ~old_cksum & 0xffff;
	sum += (~old_field & 0xffff) + new_field;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum & 0xffff;
}

static inline rte_be16_t
fixup_checksum_32(rte_be16_t old_cksum, ip4_addr_t old_addr, ip4_addr_t new_addr) {
	uint32_t sum;

	// Checksum 32-bit datum as as two 16-bit.  Note, the first
	// 32->16 bit reduction is not necessary.
	sum = ~old_cksum & 0xffff;
	sum += (~old_addr & 0xffff) + (new_addr & 0xffff);
	sum += (~old_addr >> 16) + (new_addr >> 16);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum & 0xffff;
}

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
