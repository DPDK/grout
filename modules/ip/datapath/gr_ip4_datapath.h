// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_control_output.h>
#include <gr_iface.h>
#include <gr_ip4_control.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
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

GR_NH_PRIV_DATA_TYPE(dnat44_nh_data, { ip4_addr_t replace; });

void ip_input_register_nexthop_type(gr_nh_type_t type, const char *next_node);
void ip_input_local_add_proto(uint8_t proto, const char *next_node);
void ip_output_register_interface_type(gr_iface_type_t type, const char *next_node);
void ip_output_register_nexthop_type(gr_nh_type_t type, const char *next_node);
int arp_output_request_solicit(struct nexthop *nh);
void arp_update_nexthop(
	struct rte_graph *graph,
	struct rte_node *node,
	struct nexthop *nh,
	const struct iface *iface,
	const struct rte_ether_addr *mac
);

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

void snat44_process(const struct iface *, struct rte_ipv4_hdr *);
