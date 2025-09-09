// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack_control.h>
#include <gr_iface.h>
#include <gr_nat_datapath.h>
#include <gr_net_types.h>

#include <rte_icmp.h>
#include <rte_ip4.h>
#include <rte_tcp.h>
#include <rte_udp.h>

nat_verdict_t snat44_dynamic_process(const struct iface *iface, struct rte_mbuf *m) {
	struct rte_ipv4_hdr *ip;
	struct conn_key fwd_key;
	struct nat44 *nat;
	struct conn *conn;
	conn_flow_t flow;

	// Initialize conntrack key from the IP and L4 layers.
	if (!gr_conn_parse_key(iface, GR_AF_IP4, m, &fwd_key))
		return NAT_VERDICT_DROP; // cannot NAT this type of traffic

	conn = gr_conn_lookup(&fwd_key, &flow);
	if (conn == NULL) {
		conn = snat44_conntrack_create(&fwd_key);
		if (conn == NULL)
			return NAT_VERDICT_DROP;
		flow = CONN_FLOW_FWD;
	}

	// Perform source NAT.
	nat = &conn->nat;
	ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	ip->hdr_checksum = fixup_checksum_32(ip->hdr_checksum, ip->src_addr, nat->tran_addr);

	switch (ip->next_proto_id) {
	case IPPROTO_TCP: {
		struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
			m, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
		);
		tcp->cksum = fixup_checksum_32(tcp->cksum, ip->src_addr, nat->tran_addr);
		tcp->cksum = fixup_checksum_16(tcp->cksum, tcp->src_port, nat->tran_id);
		tcp->src_port = nat->tran_id;
		break;
	}
	case IPPROTO_UDP: {
		struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
			m, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
		);
		if (udp->dgram_cksum != 0) {
			udp->dgram_cksum = fixup_checksum_32(
				udp->dgram_cksum, ip->src_addr, nat->tran_addr
			);
			udp->dgram_cksum = fixup_checksum_16(
				udp->dgram_cksum, udp->src_port, nat->tran_id
			);
			if (udp->dgram_cksum == RTE_BE16(0)) {
				// Prevent UDP checksum from becoming 0 (RFC 768).
				udp->dgram_cksum = RTE_BE16(0xffff);
			}
		}
		udp->src_port = nat->tran_id;
		break;
	}
	case IPPROTO_ICMP: {
		struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(
			m, struct rte_icmp_hdr *, rte_ipv4_hdr_len(ip)
		);
		icmp->icmp_cksum = fixup_checksum_16(
			icmp->icmp_cksum, icmp->icmp_ident, nat->tran_id
		);
		icmp->icmp_ident = nat->tran_id;
		break;
	}
	}

	// Modify the source address *after* updating the TCP/UDP checksum.
	// We need the old address value to fixup the checksum properly.
	ip->src_addr = nat->tran_addr;

	// Update conntrack state and timestamp.
	gr_conn_update(
		conn,
		flow,
		rte_pktmbuf_mtod_offset(m, const struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip))
	);

	return NAT_VERDICT_FINAL;
}
