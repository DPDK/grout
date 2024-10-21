// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_icmp6.h"
#include "gr_trace.h"

#include <gr_log.h>
#include <gr_net_types.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>

static ssize_t trace_icmp6(
	char *buf,
	const size_t len,
	const struct rte_mbuf *,
	size_t *offset,
	uint16_t payload_len
);

void trace_log_packet(const struct rte_mbuf *m, const char *node, const char *iface) {
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

	if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
		uint16_t vlan_id = m->vlan_tci & 0xfff;
		n += snprintf(buf + n, sizeof(buf) - n, " / VLAN id=%u", vlan_id);
	} else if (ether_type == RTE_ETHER_TYPE_VLAN) {
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

			if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST && icmp->icmp_code == 0) {
				n += snprintf(buf + n, sizeof(buf) - n, " echo request");
			} else if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REPLY
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
	case RTE_ETHER_TYPE_IPV6: {
		const struct rte_ipv6_hdr *ip6;
		uint16_t payload_len;
		int proto;

		ip6 = rte_pktmbuf_mtod_offset(m, const struct rte_ipv6_hdr *, offset);
		offset += sizeof(*ip6);
		inet_ntop(AF_INET6, &ip6->src_addr, src, sizeof(src));
		inet_ntop(AF_INET6, &ip6->dst_addr, dst, sizeof(dst));
		n += snprintf(
			buf + n,
			sizeof(buf) - n,
			" / IPv6 %s > %s ttl=%hhu",
			src,
			dst,
			ip6->hop_limits
		);
		payload_len = rte_be_to_cpu_16(ip6->payload_len);
		proto = ip6->proto;

		for (;;) {
			size_t ext_size = 0;
			int next_proto = rte_ipv6_get_next_ext(
				rte_pktmbuf_mtod_offset(m, const uint8_t *, offset),
				proto,
				&ext_size
			);
			if (next_proto < 0)
				break;
			if (proto != IPPROTO_HOPOPTS)
				n += snprintf(
					buf + n,
					sizeof(buf) - n,
					" Ext(%hhu len=%zu)",
					proto,
					ext_size
				);
			offset += ext_size;
			payload_len -= ext_size;
			proto = next_proto;
		};

		switch (proto) {
		case IPPROTO_ICMPV6:
			n += trace_icmp6(buf + n, sizeof(buf) - n, m, &offset, payload_len);
			break;
		default:
			n += snprintf(buf + n, sizeof(buf) - n, " nh=%hhu", proto);
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

static ssize_t trace_icmp6(
	char *buf,
	const size_t len,
	const struct rte_mbuf *m,
	size_t *offset,
	uint16_t payload_len
) {
	const struct icmp6 *icmp6;
	const struct icmp6_opt *opt = NULL;
	char dst[INET6_ADDRSTRLEN];
	ssize_t n = 0;

	n += snprintf(buf + n, len - n, " / ICMPv6");
	icmp6 = rte_pktmbuf_mtod_offset(m, const struct icmp6 *, *offset);
	*offset += sizeof(*icmp6);
	payload_len -= sizeof(*icmp6);

	switch (icmp6->type) {
	case ICMP6_ERR_DEST_UNREACH:
		n += snprintf(buf + n, len - n, " destination unreachable");
		break;
	case ICMP6_ERR_PKT_TOO_BIG:
		n += snprintf(buf + n, len - n, " packet too big");
		break;
	case ICMP6_ERR_TTL_EXCEEDED:
		n += snprintf(buf + n, len - n, " ttl exceeded");
		break;
	case ICMP6_ERR_PARAM_PROBLEM:
		n += snprintf(buf + n, len - n, " parameter problem");
		break;
	case ICMP6_TYPE_ECHO_REQUEST: {
		const struct icmp6_echo_request *req = PAYLOAD(icmp6);
		*offset += sizeof(*req);
		payload_len -= sizeof(*req);
		n += snprintf(
			buf + n,
			len - n,
			" echo request id=%u seq=%u",
			rte_be_to_cpu_16(req->ident),
			rte_be_to_cpu_16(req->seqnum)
		);
		break;
	}
	case ICMP6_TYPE_ECHO_REPLY: {
		const struct icmp6_echo_reply *reply = PAYLOAD(icmp6);
		*offset += sizeof(*reply);
		payload_len -= sizeof(*reply);
		n += snprintf(
			buf + n,
			len - n,
			" echo reply id=%u seq=%u",
			rte_be_to_cpu_16(reply->ident),
			rte_be_to_cpu_16(reply->seqnum)
		);
		break;
	}
	case ICMP6_TYPE_ROUTER_SOLICIT:
		const struct icmp6_router_solicit *rs = PAYLOAD(icmp6);
		*offset += sizeof(*rs);
		payload_len -= sizeof(*rs);
		n += snprintf(buf + n, len - n, " router solicit");
		opt = PAYLOAD(rs);
		break;
	case ICMP6_TYPE_ROUTER_ADVERT:
		const struct icmp6_router_advert *ra = PAYLOAD(icmp6);
		*offset += sizeof(*ra);
		payload_len -= sizeof(*ra);
		n += snprintf(buf + n, len - n, " router advert");
		opt = PAYLOAD(ra);
		break;
	case ICMP6_TYPE_NEIGH_SOLICIT: {
		const struct icmp6_neigh_solicit *ns = PAYLOAD(icmp6);
		*offset += sizeof(*ns);
		payload_len -= sizeof(*ns);
		inet_ntop(AF_INET6, &ns->target, dst, sizeof(dst));
		n += snprintf(buf + n, len - n, " neigh solicit who has %s?", dst);
		opt = PAYLOAD(ns);
		break;
	}
	case ICMP6_TYPE_NEIGH_ADVERT: {
		const struct icmp6_neigh_advert *na = PAYLOAD(icmp6);
		*offset += sizeof(*na);
		payload_len -= sizeof(*na);
		inet_ntop(AF_INET6, &na->target, dst, sizeof(dst));
		n += snprintf(buf + n, len - n, " neigh advert %s is at", dst);
		opt = PAYLOAD(na);
		break;
	}
	default:
		n += snprintf(buf + n, len - n, " type=%hhu code=%hhu", icmp6->type, icmp6->code);
		payload_len = 0;
		break;
	}

	while (payload_len >= 8 && opt != NULL) {
		switch (opt->type) {
		case ICMP6_OPT_SRC_LLADDR: {
			const struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			n += snprintf(
				buf + n,
				len - n,
				" / Option src_lladdr=" ETH_ADDR_FMT,
				ETH_ADDR_SPLIT(&ll->mac)
			);
			break;
		}
		case ICMP6_OPT_TARGET_LLADDR: {
			const struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			n += snprintf(
				buf + n,
				len - n,
				" / Option target_lladdr=" ETH_ADDR_FMT,
				ETH_ADDR_SPLIT(&ll->mac)
			);
			break;
		}
		default:
			n += snprintf(
				buf + n,
				len - n,
				" / Option type=%hhu len=%u(%u)",
				opt->type,
				opt->len * 8,
				opt->len
			);
			break;
		}
		*offset += opt->len * 8;
		payload_len -= opt->len * 8;
		opt = rte_pktmbuf_mtod_offset(m, const struct icmp6_opt *, *offset);
	}

	return n;
}
