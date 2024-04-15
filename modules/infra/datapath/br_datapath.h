// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_DATAPATH
#define _BR_INFRA_DATAPATH

#include <br_log.h>
#include <br_net_types.h>

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <stdint.h>

void *br_datapath_loop(void *priv);

void br_classify_add_proto(rte_be16_t eth_type, rte_edge_t edge);

#ifdef TRACE_PACKETS
static inline void trace_packet(const char *node, const struct rte_mbuf *m) {
	const struct rte_ether_hdr *eth;
	struct rte_ether_hdr eth_;

	eth = rte_pktmbuf_read(m, 0, sizeof(eth_), &eth_);
	if (ntohs(eth->ether_type) == 0x0800) {
		const struct rte_ipv4_hdr *ip;
		struct rte_ipv4_hdr ip_;
		char src[64], dst[64];

		ip = rte_pktmbuf_read(m, sizeof(eth_), sizeof(ip_), &ip_);
		inet_ntop(AF_INET, &ip->src_addr, src, sizeof(src));
		inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof(dst));

		LOG(INFO,
		    "[%s] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " type=0x%04x len=%u"
		    " / %s > %s ttl=%hhu len=%u proto=%hhu",
		    node,
		    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
		    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
		    rte_be_to_cpu_16(eth->ether_type),
		    m->pkt_len,
		    src,
		    dst,
		    ip->time_to_live,
		    ntohs(ip->total_length),
		    ip->next_proto_id);
	} else {
		LOG(INFO,
		    "[%s] " ETH_ADDR_FMT " > " ETH_ADDR_FMT " type=0x%04x len=%u",
		    node,
		    ETH_BYTES_SPLIT(eth->src_addr.addr_bytes),
		    ETH_BYTES_SPLIT(eth->dst_addr.addr_bytes),
		    rte_be_to_cpu_16(eth->ether_type),
		    m->pkt_len);
	}
}
#else
#define trace_packet(node, mbuf)
#endif // TRACE_PACKETS

#endif
