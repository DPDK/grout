// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_IP6_DATAPATH_H
#define _GR_IP6_DATAPATH_H

#include <gr_control_output.h>
#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6_control.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_ip6.h>

#include <stdint.h>

GR_MBUF_PRIV_DATA_TYPE(ip6_output_mbuf_data, { const struct nexthop *nh; });

GR_MBUF_PRIV_DATA_TYPE(ip6_local_mbuf_data, {
	struct rte_ipv6_addr src;
	struct rte_ipv6_addr dst;
	uint16_t len;
	uint8_t hop_limit;
	uint8_t proto;
});

GR_MBUF_PRIV_DATA_TYPE(ndp_na_output_mbuf_data, {
	const struct nexthop *local;
	const struct nexthop *remote;
});

void ip6_input_local_add_proto(uint8_t proto, const char *next_node);
void ip6_output_register_interface(uint16_t iface_type_id, const char *next_node);
int ip6_nexthop_solicit(struct nexthop *nh);

#define IP6_DEFAULT_HOP_LIMIT 255

static inline void ip6_set_fields(
	struct rte_ipv6_hdr *ip,
	uint16_t len,
	uint8_t proto,
	const struct rte_ipv6_addr *src,
	const struct rte_ipv6_addr *dst
) {
	ip->vtc_flow = RTE_BE32(0x60000000);
	ip->payload_len = rte_cpu_to_be_16(len);
	ip->proto = proto;
	ip->hop_limits = IP6_DEFAULT_HOP_LIMIT;
	ip->src_addr = *src;
	ip->dst_addr = *dst;
}

void ndp_update_nexthop(
	struct rte_graph *graph,
	struct rte_node *node,
	struct nexthop *nh,
	const struct iface *iface,
	const struct rte_ether_addr *mac
);

int icmp6_local_send(
	const struct rte_ipv6_addr *dst,
	const struct nexthop *gw,
	uint16_t ident,
	uint16_t seq_num,
	uint8_t hop_limit
);

void icmp6_input_register_callback(uint8_t icmp6_type, control_output_cb_t cb);

#endif
