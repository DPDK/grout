// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_DATAPATH_H
#define _GR_IP4_DATAPATH_H

#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include <stdint.h>

GR_MBUF_PRIV_DATA_TYPE(ip_output_mbuf_data, {
	struct nexthop *nh;
	const struct iface *input_iface;
});

GR_MBUF_PRIV_DATA_TYPE(arp_mbuf_data, {
	struct nexthop *local;
	struct nexthop *remote;
});

GR_MBUF_PRIV_DATA_TYPE(ip_local_mbuf_data, {
	ip4_addr_t src;
	ip4_addr_t dst;
	uint16_t len;
	uint16_t vrf_id;
	uint8_t proto;
});

void ip_input_local_add_proto(uint8_t proto, const char *next_node);
void ip_output_add_tunnel(uint16_t iface_type_id, const char *next_node);
int arp_output_request_solicit(struct nexthop *nh);

#define IPV4_VERSION_IHL 0x45
#define IPV4_DEFAULT_TTL 64

static inline void ip_set_fields(struct rte_ipv4_hdr *ip, struct ip_local_mbuf_data *data) {
	ip->version_ihl = IPV4_VERSION_IHL;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(data->len + rte_ipv4_hdr_len(ip));
	ip->fragment_offset = 0;
	ip->packet_id = 0;
	ip->time_to_live = IPV4_DEFAULT_TTL; // make this confgurable somehow?
	ip->next_proto_id = data->proto;
	ip->src_addr = data->src;
	ip->dst_addr = data->dst;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
}

#define GR_IP_ICMP_TTL_EXCEEDED 11

#endif
