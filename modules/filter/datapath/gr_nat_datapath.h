// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ip.h>

GR_NH_PRIV_DATA_TYPE(dnat44_nh_data, { ip4_addr_t replace; });

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

bool snat44_static_process(const struct iface *, struct rte_mbuf *);
