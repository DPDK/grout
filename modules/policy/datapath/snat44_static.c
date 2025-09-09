// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_nat_control.h>
#include <gr_nat_datapath.h>

bool snat44_static_process(const struct iface *iface, struct rte_ipv4_hdr *ip) {
	ip4_addr_t replace;

	if (!snat44_static_lookup_translation(iface->id, ip->src_addr, &replace))
		return false;

	ip->hdr_checksum = fixup_checksum_32(ip->hdr_checksum, ip->src_addr, replace);
	ip->src_addr = replace;

	return true;
}
