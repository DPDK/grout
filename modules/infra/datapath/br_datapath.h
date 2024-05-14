// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_DATAPATH
#define _BR_INFRA_DATAPATH

#include <br_log.h>
#include <br_net_types.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

void *br_datapath_loop(void *priv);

#ifdef TRACE_PACKETS
static inline void trace_packet(const char *node, const struct rte_mbuf *m) {
	const struct rte_ether_hdr *eth;
	rte_be16_t ether_type;

	eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth->ether_type);
	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4: {
		const struct rte_ipv4_hdr *ip;
		char src[64], dst[64];

		ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, sizeof(*eth));
		inet_ntop(AF_INET, &ip->src_addr, src, sizeof(src));
		inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof(dst));

		LOG(NOTICE,
		    "[%s p%u] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " / IP"
		    " %s > %s ttl=%hhu len=%u proto=%hhu",
		    node,
		    m->port,
		    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
		    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
		    src,
		    dst,
		    ip->time_to_live,
		    ntohs(ip->total_length),
		    ip->next_proto_id);
		break;
	}
	case RTE_ETHER_TYPE_ARP: {
		const struct rte_arp_hdr *arp;
		char src[64], dst[64];

		arp = rte_pktmbuf_mtod_offset(m, const struct rte_arp_hdr *, sizeof(*eth));
		inet_ntop(AF_INET, &arp->arp_data.arp_sip, src, sizeof(src));
		inet_ntop(AF_INET, &arp->arp_data.arp_tip, dst, sizeof(dst));

		uint16_t op = rte_be_to_cpu_16(arp->arp_opcode);
		if (op == RTE_ARP_OP_REQUEST) {
			LOG(NOTICE,
			    "[%s p%u] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " / ARP"
			    " request who has %s? tell %s",
			    node,
			    m->port,
			    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
			    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
			    dst,
			    src);
			break;
		} else if (op == RTE_ARP_OP_REPLY) {
			LOG(NOTICE,
			    "[%s p%u] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " / ARP"
			    " reply %s is at " ETH_ADDR_FMT,
			    node,
			    m->port,
			    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
			    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
			    src,
			    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes));
			break;
		}
		__attribute__((fallthrough));
	}
	default:
		LOG(NOTICE,
		    "[%s p%u] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " type=0x%04x len=%u",
		    node,
		    m->port,
		    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
		    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
		    ether_type,
		    m->pkt_len);
		break;
	}
}
#else
#define trace_packet(node, mbuf)
#endif // TRACE_PACKETS

#endif
