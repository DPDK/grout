// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP4_DATAPATH_H
#define _GR_IP4_DATAPATH_H

#include <gr_control_output.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include <stdint.h>

GR_MBUF_PRIV_DATA_TYPE(ip_output_mbuf_data, { const struct nexthop *nh; });

GR_MBUF_PRIV_DATA_TYPE(arp_reply_mbuf_data, { const struct nexthop *local; });

GR_MBUF_PRIV_DATA_TYPE(ip_local_mbuf_data, {
	ip4_addr_t src;
	ip4_addr_t dst;
	uint16_t len;
	uint16_t vrf_id;
	uint8_t proto;
	uint8_t ttl;
});

void ip_input_local_add_proto(uint8_t proto, const char *next_node);
void ip_output_register_interface_type(gr_iface_type_t type, const char *next_node);
int arp_output_request_solicit(struct nexthop *nh);
void arp_update_nexthop(struct rte_graph *, struct rte_node *, struct nexthop *, const struct iface *, const struct rte_ether_addr *);

#define IPV4_VERSION_IHL 0x45
#define IPV4_DEFAULT_TTL 64

static inline void ip_set_fields(struct rte_ipv4_hdr *ip, struct ip_local_mbuf_data *data) {
	ip->version_ihl = IPV4_VERSION_IHL;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(data->len + rte_ipv4_hdr_len(ip));
	ip->fragment_offset = 0;
	ip->packet_id = 0;
	ip->time_to_live = data->ttl ?: IPV4_DEFAULT_TTL;
	ip->next_proto_id = data->proto;
	ip->src_addr = data->src;
	ip->dst_addr = data->dst;
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);
}

int icmp_local_send(
	uint16_t vrf_id,
	ip4_addr_t dst,
	const struct nexthop *gw,
	uint16_t ident,
	uint16_t seq_num,
	uint8_t ttl
);

void icmp_input_register_callback(uint8_t icmp_type, control_output_cb_t cb);

#endif
