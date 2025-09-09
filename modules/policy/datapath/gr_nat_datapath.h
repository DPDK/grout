// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_net_types.h>
#include <gr_nh_control.h>

#include <rte_ip.h>

GR_NH_PRIV_DATA_TYPE(dnat44_nh_data, { ip4_addr_t replace; });

static inline rte_be16_t
fixup_checksum(rte_be16_t old_cksum, ip4_addr_t old_addr, ip4_addr_t new_addr) {
	uint32_t sum, old, new;

	old = rte_be_to_cpu_32(old_addr);
	new = rte_be_to_cpu_32(new_addr);

	sum = ~rte_be_to_cpu_16(old_cksum) & 0xffff;
	sum += (~old & 0xffff) + (new & 0xffff);
	sum += (~old >> 16) + (new >> 16);
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return rte_cpu_to_be_16(~sum & 0xffff);
}

bool snat44_static_process(const struct iface *, struct rte_ipv4_hdr *);
