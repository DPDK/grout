// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_nat_control.h>
#include <gr_nat_datapath.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

bool snat44_static_process(const struct iface *iface, struct rte_mbuf *mbuf) {
	struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(mbuf, struct rte_ipv4_hdr *);
	ip4_addr_t replace;
	uint16_t frag;

	if (!snat44_static_lookup_translation(iface->id, ip->src_addr, &replace))
		return false;

	ip->hdr_checksum = fixup_checksum_32(ip->hdr_checksum, ip->src_addr, replace);

	frag = rte_be_to_cpu_16(ip->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK;
	if (frag == 0) {
		// Only update the L4 checksum on first fragments.
		switch (ip->next_proto_id) {
		case IPPROTO_TCP: {
			struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
				mbuf, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
			);
			tcp->cksum = fixup_checksum_32(tcp->cksum, ip->src_addr, replace);
			break;
		}
		case IPPROTO_UDP: {
			struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
				mbuf, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
			);
			if (udp->dgram_cksum != RTE_BE16(0)) {
				udp->dgram_cksum = fixup_checksum_32(
					udp->dgram_cksum, ip->src_addr, replace
				);
				if (udp->dgram_cksum == RTE_BE16(0)) {
					// Prevent UDP checksum from becoming 0 (RFC 768).
					udp->dgram_cksum = RTE_BE16(0xffff);
				}
			}
			break;
		}
		}
	}

	// Modify the address *after* updating the TCP/UDP checksum.
	// We need the old address value to fixup the checksum properly.
	ip->src_addr = replace;

	return true;
}
