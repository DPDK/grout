// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack.h>
#include <gr_id_pool.h>
#include <gr_iface.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nat_datapath.h>
#include <gr_net_types.h>
#include <gr_rcu.h>
#include <gr_vec.h>

#include <rte_common.h>
#include <rte_hash.h>
#include <rte_icmp.h>
#include <rte_ip4.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <rte_tcp.h>
#include <rte_udp.h>

static struct gr_id_pool *tcp_ports;
static struct gr_id_pool *udp_ports;
static struct gr_id_pool *icmp_ids;
static rte_spinlock_t tcp_ports_lock;
static rte_spinlock_t udp_ports_lock;
static rte_spinlock_t icmp_ids_lock;

static void source_nat_fwd(struct rte_mbuf *m, struct nat44 *nat) {
	struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);

	ip->hdr_checksum = fixup_checksum_32(ip->hdr_checksum, ip->src_addr, nat->tran_addr);

	switch (ip->next_proto_id) {
	case IPPROTO_TCP: {
		struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(
			m, struct rte_tcp_hdr *, rte_ipv4_hdr_len(ip)
		);
		tcp->cksum = fixup_checksum_32(tcp->cksum, ip->src_addr, nat->tran_addr);
		tcp->cksum = fixup_checksum_16(tcp->cksum, tcp->src_port, nat->tran_id);
		tcp->src_port = nat->tran_id;
		break;
	}
	case IPPROTO_UDP: {
		struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(
			m, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip)
		);
		if (udp->dgram_cksum != 0) {
			udp->dgram_cksum = fixup_checksum_32(
				udp->dgram_cksum, ip->src_addr, nat->tran_addr
			);
			udp->dgram_cksum = fixup_checksum_16(
				udp->dgram_cksum, udp->src_port, nat->tran_id
			);
		}
		udp->src_port = nat->tran_id;
		break;
	}
	case IPPROTO_ICMP: {
		struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(
			m, struct rte_icmp_hdr *, rte_ipv4_hdr_len(ip)
		);
		icmp->icmp_cksum = fixup_checksum_16(
			icmp->icmp_cksum, icmp->icmp_ident, nat->tran_id
		);
		icmp->icmp_ident = nat->tran_id;
		break;
	}
	}

	ip->src_addr = nat->tran_addr;
}

static struct conn *nat44_conn_lookup(const struct iface *iface, struct rte_mbuf *m) {
	struct conn_key fwd_key, rev_key;
	rte_be16_t trans_port;
	struct conn *conn;
	conn_flow_t flow;

	// initialize conntrack key from the IP and L4 layers
	if (!gr_conn_parse_key(iface, GR_AF_IP4, m, &fwd_key))
		return NULL;

	conn = gr_conn_lookup(&fwd_key, &flow);
	if (conn == NULL) {
		// no existing connection object; search all policies for a matching one
		const struct gr_snat44_policy *policy = snat44_dynamic_policy_lookup(&fwd_key);
		if (policy == NULL)
			return NULL; // XXX: if no rule found, maybe drop the packet?

		rev_key.af = fwd_key.af;
		rev_key.src.ipv4 = fwd_key.dst.ipv4;
		rev_key.dst.ipv4 = policy->replace;
		rev_key.proto = fwd_key.proto;
		rev_key.iface_id = fwd_key.iface_id;

		switch (fwd_key.proto) {
		case IPPROTO_TCP:
			rte_spinlock_lock(&tcp_ports_lock);
			trans_port = rte_cpu_to_be_16(gr_id_pool_get(tcp_ports));
			rte_spinlock_unlock(&tcp_ports_lock);
			rev_key.src_id = fwd_key.dst_id;
			rev_key.dst_id = trans_port;
			break;
		case IPPROTO_UDP:
			rte_spinlock_lock(&udp_ports_lock);
			trans_port = rte_cpu_to_be_16(gr_id_pool_get(udp_ports));
			rte_spinlock_unlock(&udp_ports_lock);
			rev_key.src_id = fwd_key.dst_id;
			rev_key.dst_id = trans_port;
			break;
		case IPPROTO_ICMP:
			rte_spinlock_lock(&icmp_ids_lock);
			trans_port = rte_cpu_to_be_16(gr_id_pool_get(icmp_ids));
			rte_spinlock_unlock(&icmp_ids_lock);
			rev_key.src_id = trans_port;
			rev_key.dst_id = trans_port;
			break;
		default:
			return NULL;
		}
		if (trans_port == 0)
			return NULL; // available ports/ids exhausted

		conn = gr_conn_insert(&fwd_key, &rev_key);
		if (conn == NULL) {
			// give the allocated port/ID back to its pool
			switch (fwd_key.proto) {
			case IPPROTO_TCP:
				rte_spinlock_lock(&tcp_ports_lock);
				gr_id_pool_put(tcp_ports, rte_be_to_cpu_16(trans_port));
				rte_spinlock_unlock(&tcp_ports_lock);
				break;
			case IPPROTO_UDP:
				rte_spinlock_lock(&udp_ports_lock);
				gr_id_pool_put(udp_ports, rte_be_to_cpu_16(trans_port));
				rte_spinlock_unlock(&udp_ports_lock);
				break;
			case IPPROTO_ICMP:
				rte_spinlock_lock(&icmp_ids_lock);
				gr_id_pool_put(icmp_ids, rte_be_to_cpu_16(trans_port));
				rte_spinlock_unlock(&icmp_ids_lock);
				break;
			}
			return NULL; // connection pool exhausted
		}

		conn->nat = (struct nat44) {
			.orig_addr = fwd_key.src.ipv4,
			.tran_addr = policy->replace,
			.orig_id = fwd_key.src_id,
			.tran_id = trans_port,
			.policy = policy,
		};
		flow = CONN_FLOW_FWD;
	}

	gr_conn_update(
		conn,
		flow,
		rte_pktmbuf_mtod_offset(
			m,
			const struct rte_tcp_hdr *,
			rte_ipv4_hdr_len(rte_pktmbuf_mtod(m, const struct rte_ipv4_hdr *))
		)
	);

	return conn;
}

bool snat44_dynamic_process(const struct iface *iface, struct rte_mbuf *m) {
	struct conn *conn = nat44_conn_lookup(iface, m);
	if (conn == NULL)
		return false;

	source_nat_fwd(m, &conn->nat);

	return true;
}

void gr_conn_snat44_free_ports(const struct conn *conn) {
	switch (conn->fwd_key.proto) {
	case IPPROTO_TCP:
		rte_spinlock_lock(&tcp_ports_lock);
		gr_id_pool_put(tcp_ports, rte_be_to_cpu_16(conn->nat.tran_id));
		rte_spinlock_unlock(&tcp_ports_lock);
		break;
	case IPPROTO_UDP:
		rte_spinlock_lock(&udp_ports_lock);
		gr_id_pool_put(udp_ports, rte_be_to_cpu_16(conn->nat.tran_id));
		rte_spinlock_unlock(&udp_ports_lock);
		break;
	case IPPROTO_ICMP:
		rte_spinlock_lock(&icmp_ids_lock);
		gr_id_pool_put(icmp_ids, rte_be_to_cpu_16(conn->nat.tran_id));
		rte_spinlock_unlock(&icmp_ids_lock);
		break;
	}
}

static void snat44_init(struct event_base *) {
	rte_spinlock_init(&tcp_ports_lock);
	rte_spinlock_init(&udp_ports_lock);
	rte_spinlock_init(&icmp_ids_lock);

	tcp_ports = gr_id_pool_create("tcp", UINT16_MAX);
	if (tcp_ports == NULL)
		ABORT("gr_id_pool_create(tcp)");
	udp_ports = gr_id_pool_create("udp", UINT16_MAX);
	if (udp_ports == NULL)
		ABORT("gr_id_pool_create(udp)");
	icmp_ids = gr_id_pool_create("icmp", UINT16_MAX);
	if (icmp_ids == NULL)
		ABORT("gr_id_pool_create(icmp)");

	// reserve low ports for local daemons
	for (unsigned i = 1; i < 16384; i++) {
		gr_id_pool_book(tcp_ports, i);
		gr_id_pool_book(udp_ports, i);
	}
}

static void snat44_fini(struct event_base *) {
	gr_id_pool_destroy(tcp_ports);
	gr_id_pool_destroy(udp_ports);
	gr_id_pool_destroy(icmp_ids);
}

static struct gr_module module = {
	.name = "snat44-dynamic",
	.init = snat44_init,
	.fini = snat44_fini,
};

RTE_INIT(_init) {
	gr_register_module(&module);
}
