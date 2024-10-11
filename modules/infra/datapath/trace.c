// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_graph.h>
#include <gr_icmp6.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_trace.h>

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

void trace_log_packet(const struct rte_mbuf *m, const char *node, const char *iface) {
	char buf[BUFSIZ], src[64], dst[64];
	const struct rte_ether_hdr *eth;
	uint16_t ether_type;
	size_t offset = 0;
	size_t n = 0;

	eth = rte_pktmbuf_mtod_offset(m, const struct rte_ether_hdr *, offset);
	offset += sizeof(*eth);
	ether_type = rte_be_to_cpu_16(eth->ether_type);

	SAFE_BUF(
		snprintf,
		sizeof(buf),
		ETH_ADDR_FMT " > " ETH_ADDR_FMT,
		ETH_ADDR_SPLIT(&eth->src_addr),
		ETH_ADDR_SPLIT(&eth->dst_addr)
	);

	if (m->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
		uint16_t vlan_id = m->vlan_tci & 0xfff;
		SAFE_BUF(snprintf, sizeof(buf), " / VLAN id=%u", vlan_id);
	} else if (ether_type == RTE_ETHER_TYPE_VLAN) {
		const struct rte_vlan_hdr *vlan;
		uint16_t vlan_id;

		vlan = rte_pktmbuf_mtod_offset(m, const struct rte_vlan_hdr *, offset);
		offset += sizeof(*vlan);
		vlan_id = rte_be_to_cpu_16(vlan->vlan_tci) & 0xfff;
		ether_type = rte_be_to_cpu_16(vlan->eth_proto);
		SAFE_BUF(snprintf, sizeof(buf), " / VLAN id=%u", vlan_id);
	}

	switch (ether_type) {
	case RTE_ETHER_TYPE_IPV4: {
ipv4:
		const struct rte_ipv4_hdr *ip;

		ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, offset);
		offset += sizeof(*ip);
		inet_ntop(AF_INET, &ip->src_addr, src, sizeof(src));
		inet_ntop(AF_INET, &ip->dst_addr, dst, sizeof(dst));
		SAFE_BUF(
			snprintf, sizeof(buf), " / IP %s > %s ttl=%hhu", src, dst, ip->time_to_live
		);

		switch (ip->next_proto_id) {
		case IPPROTO_ICMP: {
			const struct rte_icmp_hdr *icmp;
			icmp = rte_pktmbuf_mtod_offset(m, const struct rte_icmp_hdr *, offset);
			SAFE_BUF(snprintf, sizeof(buf), " / ICMP");

			if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST && icmp->icmp_code == 0) {
				SAFE_BUF(snprintf, sizeof(buf), " echo request");
			} else if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REPLY
				   && icmp->icmp_code == 0) {
				SAFE_BUF(snprintf, sizeof(buf), " echo reply");
			} else {
				SAFE_BUF(
					snprintf,
					sizeof(buf),
					" type=%hhu code=%hhu",
					icmp->icmp_type,
					icmp->icmp_code
				);
			}

			SAFE_BUF(
				snprintf,
				sizeof(buf),
				" id=%u seq=%u",
				rte_be_to_cpu_16(icmp->icmp_ident),
				rte_be_to_cpu_16(icmp->icmp_seq_nb)
			);
			break;
		}
		case IPPROTO_IPIP:
			goto ipv4;
		default:
			SAFE_BUF(snprintf, sizeof(buf), " proto=%hhu", ip->next_proto_id);
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
		SAFE_BUF(
			snprintf, sizeof(buf), " / IPv6 %s > %s ttl=%hhu", src, dst, ip6->hop_limits
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
				SAFE_BUF(
					snprintf, sizeof(buf), " Ext(%hhu len=%zu)", proto, ext_size
				);
			offset += ext_size;
			payload_len -= ext_size;
			proto = next_proto;
		};

		switch (proto) {
		case IPPROTO_ICMPV6:
			SAFE_BUF(trace_icmp6, sizeof(buf), m, &offset, payload_len);
			break;
		default:
			SAFE_BUF(snprintf, sizeof(buf), " nh=%hhu", proto);
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
			SAFE_BUF(
				snprintf,
				sizeof(buf),
				" / ARP request who has %s? tell %s",
				dst,
				src
			);
			break;
		case RTE_ARP_OP_REPLY:
			inet_ntop(AF_INET, &arp->arp_data.arp_sip, src, sizeof(src));
			SAFE_BUF(
				snprintf,
				sizeof(buf),
				" / ARP reply %s is at " ETH_ADDR_FMT,
				src,
				ETH_ADDR_SPLIT(&eth->src_addr)
			);
			break;
		default:
			SAFE_BUF(
				snprintf,
				sizeof(buf),
				" / ARP opcode=%u",
				rte_be_to_cpu_16(arp->arp_opcode)
			);
			break;
		}
		break;
	}
	default:
		SAFE_BUF(snprintf, sizeof(buf), " type=0x%04x", ether_type);
		break;
	}
	SAFE_BUF(snprintf, sizeof(buf), ", (pkt_len=%u)", m->pkt_len);

	LOG(NOTICE, "[%s %s] %s", node, iface, buf);
	return;
err:
	LOG(ERR, "[%s %s] snprintf failed: %s", node, iface, strerror(errno));
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

	SAFE_BUF(snprintf, len, " / ICMPv6");
	icmp6 = rte_pktmbuf_mtod_offset(m, const struct icmp6 *, *offset);
	*offset += sizeof(*icmp6);
	payload_len -= sizeof(*icmp6);

	switch (icmp6->type) {
	case ICMP6_ERR_DEST_UNREACH:
		SAFE_BUF(snprintf, len, " destination unreachable");
		break;
	case ICMP6_ERR_PKT_TOO_BIG:
		SAFE_BUF(snprintf, len, " packet too big");
		break;
	case ICMP6_ERR_TTL_EXCEEDED:
		SAFE_BUF(snprintf, len, " ttl exceeded");
		break;
	case ICMP6_ERR_PARAM_PROBLEM:
		SAFE_BUF(snprintf, len, " parameter problem");
		break;
	case ICMP6_TYPE_ECHO_REQUEST: {
		const struct icmp6_echo_request *req = PAYLOAD(icmp6);
		*offset += sizeof(*req);
		payload_len -= sizeof(*req);
		SAFE_BUF(
			snprintf,
			len,
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
		SAFE_BUF(
			snprintf,
			len,
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
		SAFE_BUF(snprintf, len, " router solicit");
		opt = PAYLOAD(rs);
		break;
	case ICMP6_TYPE_ROUTER_ADVERT:
		const struct icmp6_router_advert *ra = PAYLOAD(icmp6);
		*offset += sizeof(*ra);
		payload_len -= sizeof(*ra);
		SAFE_BUF(snprintf, len, " router advert");
		opt = PAYLOAD(ra);
		break;
	case ICMP6_TYPE_NEIGH_SOLICIT: {
		const struct icmp6_neigh_solicit *ns = PAYLOAD(icmp6);
		*offset += sizeof(*ns);
		payload_len -= sizeof(*ns);
		inet_ntop(AF_INET6, &ns->target, dst, sizeof(dst));
		SAFE_BUF(snprintf, len, " neigh solicit who has %s?", dst);
		opt = PAYLOAD(ns);
		break;
	}
	case ICMP6_TYPE_NEIGH_ADVERT: {
		const struct icmp6_neigh_advert *na = PAYLOAD(icmp6);
		*offset += sizeof(*na);
		payload_len -= sizeof(*na);
		inet_ntop(AF_INET6, &na->target, dst, sizeof(dst));
		SAFE_BUF(snprintf, len, " neigh advert %s is at", dst);
		opt = PAYLOAD(na);
		break;
	}
	default:
		SAFE_BUF(snprintf, len, " type=%hhu code=%hhu", icmp6->type, icmp6->code);
		payload_len = 0;
		break;
	}

	while (payload_len >= 8 && opt != NULL) {
		switch (opt->type) {
		case ICMP6_OPT_SRC_LLADDR: {
			const struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			SAFE_BUF(
				snprintf,
				len,
				" / Option src_lladdr=" ETH_ADDR_FMT,
				ETH_ADDR_SPLIT(&ll->mac)
			);
			break;
		}
		case ICMP6_OPT_TARGET_LLADDR: {
			const struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			SAFE_BUF(
				snprintf,
				len,
				" / Option target_lladdr=" ETH_ADDR_FMT,
				ETH_ADDR_SPLIT(&ll->mac)
			);
			break;
		}
		default:
			SAFE_BUF(
				snprintf,
				len,
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
err:
	return -1;
}

#define PACKET_COUNT_MAX RTE_GRAPH_BURST_SIZE

static struct rte_mempool *trace_pool;
static struct rte_ring *traced_packets;

static void free_trace(struct gr_trace_item *t) {
	// free the whole chain of trace items
	while (t != NULL) {
		struct gr_trace_item *next = STAILQ_NEXT(t, next);
		rte_mempool_put(trace_pool, t);
		t = next;
	}
}

void *gr_mbuf_trace_add(struct rte_mbuf *m, struct rte_node *node, size_t data_len) {
	struct gr_trace_head *traces = gr_mbuf_traces(m);
	struct gr_trace_item *trace;
	void *data;

	// XXX: should we always abort even if -DNDEBUG is defined?
	assert(data_len <= GR_TRACE_ITEM_MAX_LEN);

	while (rte_mempool_get(trace_pool, &data) < 0) {
		void *oldest = NULL;
		rte_ring_dequeue(traced_packets, &oldest);
		free_trace(oldest);
	}

	trace = data;
	trace->node_id = node->id;
	trace->len = data_len;

	if (STAILQ_EMPTY(traces)) {
		clock_gettime(CLOCK_REALTIME_COARSE, &trace->ts);
		trace->cpu_id = rte_lcore_id();
		STAILQ_INSERT_HEAD(traces, trace, next);
	} else {
		STAILQ_INSERT_TAIL(traces, trace, next);
	}

	return trace->data;
}

void gr_mbuf_trace_finish(struct rte_mbuf *m) {
	struct gr_trace_head *traces = gr_mbuf_traces(m);
	struct gr_trace_item *trace = STAILQ_FIRST(traces);

	if (trace == NULL)
		return;

	while (rte_ring_enqueue(traced_packets, trace) == -ENOBUFS) {
		void *oldest = NULL;
		rte_ring_dequeue(traced_packets, &oldest);
		free_trace(oldest);
	}

	// Reset trace head to NULL to remove all references to the trace items.
	// This is also to ensure that reusing this mbuf will find traces disabled.
	STAILQ_INIT(traces);
}

int gr_trace_dump(char *buf, size_t len) {
	const struct gr_node_info *info;
	struct gr_trace_item *t, *head;
	struct tm tm;
	void *data;
	int n = 0;

	if (rte_ring_dequeue(traced_packets, &data) == 0) {
		t = data;
		head = t;

		gmtime_r(&t->ts.tv_sec, &tm);
		n += strftime(buf + n, len - n, "--------- %H:%M:%S.", &tm);
		SAFE_BUF(snprintf, len, "%09lu", t->ts.tv_nsec);
		SAFE_BUF(snprintf, len, " cpu %u ---------\n", t->cpu_id);

		while (t) {
			SAFE_BUF(snprintf, len, "%s:", rte_node_id_to_name(t->node_id));
			if ((info = gr_node_info_get(t->node_id)) != NULL && info->trace_format) {
				SAFE_BUF(snprintf, len, " ");
				n += info->trace_format(buf + n, len - n, t->data, t->len);
			}
			SAFE_BUF(snprintf, len, "\n");

			t = STAILQ_NEXT(t, next);
		}
		free_trace(head);
		// add empty line to separate packets
		SAFE_BUF(snprintf, len, "\n");
	}

	return n;
err:
	return -1;
}

void gr_trace_clear(void) {
	void *trace;
	while (rte_ring_dequeue(traced_packets, &trace) == 0)
		free_trace(trace);
}

static void trace_init(struct event_base *) {
	trace_pool = rte_mempool_create(
		"trace_items", // name
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
		ABORT("rte_mempool_create(trace_items) failed");
	traced_packets = rte_ring_create(
		"traced_packets",
		PACKET_COUNT_MAX,
		SOCKET_ID_ANY,
		RING_F_MP_RTS_ENQ | RING_F_SC_DEQ // flags
	);

	if (traced_packets == NULL)
		ABORT("rte_ring_create(traced_packets) failed");
}

static void trace_fini(struct event_base *) {
	gr_trace_clear();
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
