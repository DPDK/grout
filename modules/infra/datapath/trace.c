// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_datapath.h"

#include <gr_log.h>
#include <gr_net_types.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

void trace_packet(const char *node, const char *iface, const struct rte_mbuf *m) {
	char buf[BUFSIZ], src[64], dst[64];
	const struct rte_ether_hdr *eth;
	uint16_t ether_type;
	size_t offset = 0;
	ssize_t n = 0;

	eth = rte_pktmbuf_mtod_offset(m, const struct rte_ether_hdr *, offset);
	offset += sizeof(*eth);
	ether_type = rte_be_to_cpu_16(eth->ether_type);

	n += snprintf(
		buf + n,
		sizeof(buf) - n,
		ETH_ADDR_FMT " > " ETH_ADDR_FMT,
		ETH_ADDR_SPLIT(&eth->src_addr),
		ETH_ADDR_SPLIT(&eth->dst_addr)
	);

	if (ether_type == RTE_ETHER_TYPE_VLAN) {
		const struct rte_vlan_hdr *vlan;
		uint16_t vlan_id;

		vlan = rte_pktmbuf_mtod_offset(m, const struct rte_vlan_hdr *, offset);
		offset += sizeof(*vlan);
		vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xfff;
		ether_type = rte_be_to_cpu_16(vlan->eth_proto);
		n += snprintf(buf + n, sizeof(buf) - n, " / VLAN id=%u", vlan_id);
	}

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4: {
ipv4:
		const struct rte_ipv4_hdr *ip;

		ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, offset);
		offset += sizeof(*ip);
		inet_ntop(AF_INET, &ip->src_addr, src, sizeof(src));
		inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof(dst));
		n += snprintf(
			buf + n,
			sizeof(buf) - n,
			" / IP %s > %s ttl=%hhu",
			src,
			dst,
			ip->time_to_live
		);

		switch (ip->next_proto_id) {
		case IPPROTO_ICMP: {
			const struct rte_icmp_hdr *icmp;
			icmp = rte_pktmbuf_mtod_offset(m, const struct rte_icmp_hdr *, offset);
			n += snprintf(buf + n, sizeof(buf) - n, " / ICMP");

			if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST && icmp->icmp_code == 0) {
				n += snprintf(buf + n, sizeof(buf) - n, " echo request");
			} else if (icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY
				   && icmp->icmp_code == 0) {
				n += snprintf(buf + n, sizeof(buf) - n, " echo reply");
			} else {
				n += snprintf(
					buf + n,
					sizeof(buf) - n,
					" type=%hhu code=%hhu",
					icmp->icmp_type,
					icmp->icmp_code
				);
			}
			n += snprintf(
				buf + n,
				sizeof(buf) - n,
				" id=%u seq=%u",
				rte_be_to_cpu_16(icmp->icmp_ident),
				rte_be_to_cpu_16(icmp->icmp_seq_nb)
			);
			break;
		}
		case IPPROTO_IPIP:
			goto ipv4;
		default:
			n += snprintf(buf + n, sizeof(buf) - n, " proto=%hhu", ip->next_proto_id);
			break;
		}

		break;
	}
	case RTE_ETHER_TYPE_ARP: {
		const struct rte_arp_hdr *arp;

		arp = rte_pktmbuf_mtod_offset(m, const struct rte_arp_hdr *, offset);

		switch (rte_be_to_cpu_16(arp->arp_opcode)) {
		case RTE_ARP_OP_REQUEST:
			inet_ntop(AF_INET, &arp->arp_data.arp_sip, src, sizeof(src));
			inet_ntop(AF_INET, &arp->arp_data.arp_tip, dst, sizeof(dst));
			n += snprintf(
				buf + n,
				sizeof(buf) - n,
				" / ARP request who has %s? tell %s",
				dst,
				src
			);
			break;
		case RTE_ARP_OP_REPLY:
			inet_ntop(AF_INET, &arp->arp_data.arp_sip, src, sizeof(src));
			n += snprintf(
				buf + n,
				sizeof(buf) - n,
				" / ARP reply %s is at " ETH_ADDR_FMT,
				src,
				ETH_ADDR_SPLIT(&eth->src_addr)
			);
			break;
		default:
			n += snprintf(
				buf + n,
				sizeof(buf) - n,
				" / ARP opcode=%u",
				rte_be_to_cpu_16(arp->arp_opcode)
			);
			break;
		}
		break;
	}
	default:
		n += snprintf(buf + n, sizeof(buf) - n, " type=0x%04x", ether_type);
		break;
	}
	n += snprintf(buf + n, sizeof(buf) - n, ", (pkt_len=%u)", m->pkt_len);

	LOG(NOTICE, "[%s %s] %s", node, iface, buf);
}
