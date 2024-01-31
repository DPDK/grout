// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_DATAPATH
#define _BR_INFRA_DATAPATH

#include <br_log.h>
#include <br_net_types.h>

#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

#include <stdint.h>

void *br_datapath_loop(void *priv);

struct node_ctx_key {
	char key[RTE_NODE_NAMESIZE];
};

#define NODE_CTX_DATA_HASH_NAME "ctx_data"

struct rx_node_ctx {
	uint16_t port_id;
	uint16_t rxq_id;
	uint16_t burst;
};

struct tx_node_ctx {
	uint16_t port_id;
	uint16_t txq_id;
};

#define EDGE_DROP 0
#define EDGE_DEFAULT 1

struct port_edge_map {
	rte_edge_t edges[RTE_MAX_ETHPORTS];
};

static inline void copy_node_key(struct node_ctx_key *key, const char *name) {
	memset(key, 0, sizeof(*key));
	memccpy(key->key, name, 0, sizeof(key->key));
}

static inline int get_ctx_data(struct rte_node *node, void **data) {
	struct rte_hash *hash = rte_hash_find_existing(NODE_CTX_DATA_HASH_NAME);
	struct node_ctx_key key;

	if (hash == NULL)
		return -rte_errno;

	copy_node_key(&key, node->name);

	if (rte_hash_lookup_data(hash, &key, data) < 0)
		return -rte_errno;

	return 0;
}

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
#define trace_packet(node, mbuf) ((void)0)
#endif // TRACE_PACKETS

#endif
