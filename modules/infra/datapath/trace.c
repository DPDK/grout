// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_datapath.h"
#include "gr_icmp6.h"
#include "gr_trace.h"

#include <gr_control.h>
#include <gr_graph.h>
#include <gr_log.h>
#include <gr_net_types.h>

#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

static ssize_t trace_icmp6(
	char *buf,
	const size_t len,
	const struct rte_mbuf *,
	size_t *offset,
	uint16_t payload_len
);

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

#define PACKET_COUNT_MAX RTE_GRAPH_BURST_SIZE

static struct rte_mempool *trace_pool;
static struct rte_ring *traced_packets;

void *gr_trace_begin(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len) {
	struct gr_mbuf *gm = gr_mbuf(m);
	struct gr_trace_item *pt;
	void *data;

	if (rte_mempool_get(trace_pool, &data) < 0)
		return NULL;

	gm->flags |= GR_MBUF_F_PKT_TRACE;
	STAILQ_INIT(&gm->traces);
	pt = data;

	clock_gettime(CLOCK_REALTIME_COARSE, &pt->ts);
	pt->cpu_id = rte_lcore_id();

	pt->node_id = node->id;
	pt->len = data_len;

	STAILQ_INSERT_HEAD(&gm->traces, pt, next);

	return pt->data;
}

void *gr_trace_add(struct rte_node *node, struct rte_mbuf *m, uint16_t data_len) {
	struct gr_mbuf *gm = gr_mbuf(m);
	struct gr_trace_item *pt;
	void *data;

	if (rte_mempool_get(trace_pool, &data) < 0)
		return NULL;

	pt = data;
	pt->node_id = node->id;
	pt->len = data_len;

	STAILQ_INSERT_TAIL(&gm->traces, pt, next);
	return pt->data;
}

static void free_trace(struct gr_trace_item *t) {
	struct gr_trace_item *next;
	while (t != NULL) {
		next = STAILQ_NEXT(t, next);
		rte_mempool_put(trace_pool, t);
		t = next;
	}
}

void gr_trace_aggregate(struct rte_mbuf *mbuf) {
	struct gr_trace_item *t = NULL;
	struct gr_mbuf *gm = gr_mbuf(mbuf);

	gm->flags &= ~GR_MBUF_F_PKT_TRACE;
	if (rte_ring_full(traced_packets) == 1) {
		rte_ring_dequeue(traced_packets, (void *)&t);
		free_trace(t);
	}

	t = STAILQ_FIRST(&gm->traces);
	rte_ring_enqueue(traced_packets, t);
}

int trace_print(char *buf, size_t len) {
	struct gr_trace_item *t, *head;
	struct tm tm;
	size_t sz = 0;
	int c;

	if (rte_ring_dequeue(traced_packets, (void *)&t) == 0) {
		head = t;

		gmtime_r(&t->ts.tv_sec, &tm);
		sz += strftime(&buf[sz], len - sz, "--------- %H:%M:%S.", &tm);
		sz += snprintf(&buf[sz], len - sz, "%09luZ", t->ts.tv_nsec);
		sz += snprintf(&buf[sz], len - sz, " cpu %d ---------\n", t->cpu_id);

		while (t) {
			if ((c = snprintf(
				     &buf[sz], sz - len, "%s: ", rte_node_id_to_name(t->node_id)
			     ))
			    < 0)
				break;
			sz += c;
			if (gr_get_node_ext_funcs(t->node_id)->format_trace)
				c = gr_get_node_ext_funcs(t->node_id)
					    ->format_trace(t->data, &buf[sz], sz - len);
			if (c < 0)
				break;
			sz += c;
			if ((c = snprintf(&buf[sz], len - sz, "\n")) < 0)
				break;
			sz += c;
			t = STAILQ_NEXT(t, next);
		}
		free_trace(head);
		sz += snprintf(&buf[sz], len - sz, "\n");
	}
	return sz;
}

void trace_clear() {
	struct gr_trace_item *t;
	while (rte_ring_dequeue(traced_packets, (void *)&t) == 0)
		free_trace(t);
}

static void trace_init(struct event_base *) {
	trace_pool = rte_mempool_create(
		"trace", // name
		rte_align32pow2(PACKET_COUNT_MAX * 128) - 1,
		sizeof(struct gr_trace_item),
		0, // cache size
		0, // priv size
		NULL, // mp_init
		NULL, // mp_init_arg
		NULL, // obj_init
		NULL, // obj_init_arg
		SOCKET_ID_ANY,
		0 // flags
	);
	if (trace_pool == NULL)
		ABORT("rte_mempool_create(trace_pool) failed");
	traced_packets = rte_ring_create(
		"traced_packets",
		PACKET_COUNT_MAX,
		SOCKET_ID_ANY,
		RING_F_SC_DEQ // flags
	);

	if (traced_packets == NULL)
		ABORT("rte_stack_create(traced_packets) failed");
}

static void trace_fini(struct event_base *) {
	trace_clear();
	rte_mempool_free(trace_pool);
	rte_ring_free(traced_packets);
}

static struct gr_module trace_module = {
	.name = "trace",
	.init = trace_init,
	.fini = trace_fini,
};

RTE_INIT(trace_constructor) {
	gr_register_module(&trace_module);
}
