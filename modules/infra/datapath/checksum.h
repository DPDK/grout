// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Matej Muzila

#pragma once

#include <gr_net_types.h>

// RFC 1624 incremental checksum update for a 16-bit field.
static inline rte_be16_t
fixup_checksum_16(rte_be16_t old_cksum, rte_be16_t old_field, rte_be16_t new_field) {
	uint32_t sum;

	sum = ~old_cksum & 0xffff;
	sum += (~old_field & 0xffff) + new_field;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum & 0xffff;
}

// RFC 1624 incremental checksum update for a 32-bit field.
static inline rte_be16_t
fixup_checksum_32(rte_be16_t old_cksum, ip4_addr_t old_addr, ip4_addr_t new_addr) {
	uint32_t sum;

	sum = ~old_cksum & 0xffff;
	sum += (~old_addr & 0xffff) + (new_addr & 0xffff);
	sum += (~old_addr >> 16) + (new_addr >> 16);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum & 0xffff;
}
