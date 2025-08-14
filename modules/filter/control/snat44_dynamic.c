// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack_control.h>
#include <gr_control_input.h>
#include <gr_fib4.h>
#include <gr_id_pool.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nat_control.h>
#include <gr_vec.h>

#include <rte_malloc.h>

#include <stdint.h>

static uint16_t n_policies;
static struct gr_snat44_policy *policies;
static struct gr_id_pool *tcp_ports;
static struct gr_id_pool *udp_ports;
static struct gr_id_pool *icmp_ids;
static control_input_t ip_output_node;

int snat44_dynamic_policy_add(const struct gr_snat44_policy *policy) {
	struct iface *iface = iface_from_id(policy->iface_id);

	if (iface == NULL)
		return -errno;

	// What happens if a datapath worker reads policies while it is being reallocated?
	// Probably OK, but it seems unsafe.
	policies = rte_realloc(policies, (n_policies + 1) * sizeof(*policies), RTE_CACHE_LINE_SIZE);
	if (policies == NULL)
		return errno_set(ENOMEM);

	policies[n_policies++] = *policy;
	iface->flags |= GR_IFACE_F_SNAT_DYNAMIC;

	return 0;
}

int snat44_dynamic_policy_del(const struct gr_snat44_policy *policy) {
	struct iface *iface = iface_from_id(policy->iface_id);
	unsigned iface_count, deleted_count;

	if (iface == NULL)
		return -errno;

	iface_count = deleted_count = 0;

	for (unsigned i = 0; i < n_policies; i++) {
		struct gr_snat44_policy *p = &policies[i];
		if (memcmp(p, policy, sizeof(*p)) == 0) {
			n_policies--;
			if (n_policies > 0)
				policies[i] = policies[n_policies];
			i--;

			gr_conn_snat44_purge(p);

			deleted_count++;
		} else if (p->iface_id == iface->id) {
			iface_count++;
		}
	}

	if (deleted_count == 0)
		return errno_set(ENOENT);

	if (iface_count == 0)
		iface->flags &= ~GR_IFACE_F_SNAT_DYNAMIC;

	return 0;
}

struct gr_snat44_policy *snat44_dynamic_policy_export(void) {
	struct gr_snat44_policy *p = NULL;

	for (unsigned i = 0; i < n_policies; i++)
		gr_vec_add(p, policies[i]);

	return p;
}

const struct gr_snat44_policy *snat44_dynamic_policy_lookup(const struct conn_key *key) {
	for (unsigned i = 0; i < n_policies; i++) {
		const struct gr_snat44_policy *p = &policies[i];
		if (p->iface_id != key->iface_id)
			continue;
		if (ip4_addr_same_subnet(key->src.ipv4, p->net.ip, p->net.prefixlen))
			return p;
	}
	return NULL;
}

void snat44_conntrack_create_cb(struct rte_mbuf *m) {
	const struct iface *iface = mbuf_data(m)->iface;
	const struct gr_snat44_policy *policy;
	struct conn_key fwd_key, rev_key;
	rte_be16_t trans_port = 0;
	struct conn *conn;
	conn_flow_t flow;

	// initialize conntrack key from the IP and L4 layers
	if (!gr_conn_parse_key(iface, GR_AF_IP4, m, &fwd_key))
		goto drop; // should never happen

	if (gr_conn_lookup(&fwd_key, &flow) != NULL) {
		// Conntrack was created while packet was waiting for control plane.
		// Send it back to datapath.
		goto out;
	}

	policy = snat44_dynamic_policy_lookup(&fwd_key);
	if (policy == NULL)
		goto drop; // no policy found

	rev_key.af = fwd_key.af;
	rev_key.src.ipv4 = fwd_key.dst.ipv4;
	rev_key.dst.ipv4 = policy->replace;
	rev_key.proto = fwd_key.proto;
	rev_key.iface_id = fwd_key.iface_id;

	switch (fwd_key.proto) {
	case IPPROTO_TCP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get(tcp_ports));
		rev_key.src_id = fwd_key.dst_id;
		rev_key.dst_id = trans_port;
		break;
	case IPPROTO_UDP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get(udp_ports));
		rev_key.src_id = fwd_key.dst_id;
		rev_key.dst_id = trans_port;
		break;
	case IPPROTO_ICMP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get(icmp_ids));
		rev_key.src_id = trans_port;
		rev_key.dst_id = trans_port;
		break;
	}
	if (trans_port == 0)
		goto drop; // available ports/ids exhausted

	conn = gr_conn_insert(&fwd_key, &rev_key);
	if (conn == NULL) {
		// give the allocated port/ID back to its pool
		switch (fwd_key.proto) {
		case IPPROTO_TCP:
			gr_id_pool_put(tcp_ports, rte_be_to_cpu_16(trans_port));
			break;
		case IPPROTO_UDP:
			gr_id_pool_put(udp_ports, rte_be_to_cpu_16(trans_port));
			break;
		case IPPROTO_ICMP:
			gr_id_pool_put(icmp_ids, rte_be_to_cpu_16(trans_port));
			break;
		}
		goto drop; // connection pool exhausted
	}

	conn->nat = (struct nat44) {
		.orig_addr = fwd_key.src.ipv4,
		.tran_addr = policy->replace,
		.orig_id = fwd_key.src_id,
		.tran_id = trans_port,
		.policy = policy,
	};

out:
	struct ip_output_mbuf_data *d = ip_output_mbuf_data(m);
	d->nh = fib4_lookup(iface->vrf_id, fwd_key.dst.ipv4);
	if (d->nh == NULL)
		goto drop;

	post_to_stack(ip_output_node, m);
	return;
drop:
	rte_pktmbuf_free(m);
}

void gr_conn_snat44_free_ports(const struct conn *conn) {
	switch (conn->fwd_key.proto) {
	case IPPROTO_TCP:
		gr_id_pool_put(tcp_ports, rte_be_to_cpu_16(conn->nat.tran_id));
		break;
	case IPPROTO_UDP:
		gr_id_pool_put(udp_ports, rte_be_to_cpu_16(conn->nat.tran_id));
		break;
	case IPPROTO_ICMP:
		gr_id_pool_put(icmp_ids, rte_be_to_cpu_16(conn->nat.tran_id));
		break;
	}
}

static void snat44_init(struct event_base *) {
	ip_output_node = gr_control_input_register_handler("ip_output", true);

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
	.depends_on = "graph",
	.init = snat44_init,
	.fini = snat44_fini,
};

RTE_INIT(_init) {
	gr_register_module(&module);
}
