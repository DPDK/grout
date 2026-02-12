// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack_control.h>
#include <gr_id_pool.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nat_control.h>
#include <gr_rcu.h>
#include <gr_vec.h>

#include <rte_malloc.h>

#include <stdint.h>

static STAILQ_HEAD(, snat44_policy) policies = STAILQ_HEAD_INITIALIZER(policies);

int snat44_dynamic_policy_add(const struct gr_snat44_policy *p) {
	struct iface *iface = iface_from_id(p->iface_id);
	struct snat44_policy *policy;

	if (iface == NULL)
		return -errno;

	policy = rte_zmalloc(__func__, sizeof(*policy), RTE_CACHE_LINE_SIZE);
	if (policy == NULL)
		return errno_set(ENOMEM);

	policy->base = *p;
	policy->tcp_ports = gr_id_pool_create(1024, 65535);
	if (policy->tcp_ports == NULL)
		goto err;
	policy->udp_ports = gr_id_pool_create(1024, 65535);
	if (policy->udp_ports == NULL)
		goto err;
	policy->icmp_ids = gr_id_pool_create(1, 65535);
	if (policy->icmp_ids == NULL)
		goto err;

	STAILQ_INSERT_TAIL(&policies, policy, next);
	iface->flags |= GR_IFACE_F_SNAT_DYNAMIC;

	return 0;
err:
	gr_id_pool_destroy(policy->tcp_ports);
	gr_id_pool_destroy(policy->udp_ports);
	gr_id_pool_destroy(policy->icmp_ids);
	rte_free(policy);
	return errno_set(ENOMEM);
}

int snat44_dynamic_policy_del(const struct gr_snat44_policy *policy) {
	struct iface *iface = iface_from_id(policy->iface_id);
	struct snat44_policy *p, *found;
	unsigned iface_count;

	if (iface == NULL)
		return -errno;

	iface_count = 0;
	found = NULL;

	STAILQ_FOREACH (p, &policies, next) {
		if (memcmp(&p->base, policy, sizeof(*policy)) == 0)
			found = found ?: p;
		else if (p->iface_id == iface->id)
			iface_count++;
	}
	if (found == NULL)
		return errno_set(ENOENT);

	STAILQ_REMOVE(&policies, found, snat44_policy, next);

	if (iface_count == 0)
		iface->flags &= ~GR_IFACE_F_SNAT_DYNAMIC;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	gr_conn_snat44_purge(found);
	gr_id_pool_destroy(found->tcp_ports);
	gr_id_pool_destroy(found->udp_ports);
	gr_id_pool_destroy(found->icmp_ids);
	rte_free(found);

	return 0;
}

gr_vec struct gr_snat44_policy *snat44_dynamic_policy_export(void) {
	gr_vec struct gr_snat44_policy *list = NULL;
	const struct snat44_policy *p;

	STAILQ_FOREACH (p, &policies, next)
		gr_vec_add(list, p->base);

	return list;
}

static struct snat44_policy *snat44_dynamic_policy_lookup(const struct conn_key *key) {
	struct snat44_policy *p;

	STAILQ_FOREACH (p, &policies, next) {
		if (p->iface_id != key->iface_id)
			continue;
		if (ip4_addr_same_subnet(key->src, p->net.ip, p->net.prefixlen))
			return p;
	}

	return NULL;
}

struct conn *snat44_conntrack_create(const struct conn_key *fwd_key) {
	struct snat44_policy *policy;
	rte_be16_t trans_port = 0;
	struct conn_key rev_key;
	struct conn *conn;

	policy = snat44_dynamic_policy_lookup(fwd_key);
	if (policy == NULL)
		return NULL; // no policy found

	rev_key.af = fwd_key->af;
	rev_key.src = fwd_key->dst;
	rev_key.dst = policy->replace;
	rev_key.proto = fwd_key->proto;
	rev_key.iface_id = fwd_key->iface_id;

	switch (fwd_key->proto) {
	case IPPROTO_TCP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get_random(policy->tcp_ports));
		rev_key.src_id = fwd_key->dst_id;
		rev_key.dst_id = trans_port;
		break;
	case IPPROTO_UDP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get_random(policy->udp_ports));
		rev_key.src_id = fwd_key->dst_id;
		rev_key.dst_id = trans_port;
		break;
	case IPPROTO_ICMP:
		trans_port = rte_cpu_to_be_16(gr_id_pool_get_random(policy->icmp_ids));
		rev_key.src_id = trans_port;
		rev_key.dst_id = trans_port;
		break;
	}
	if (trans_port == 0)
		return NULL; // available ports/ids exhausted

	conn = gr_conn_insert(fwd_key, &rev_key);
	if (conn == NULL) {
		// put the allocated port/ID back to its pool
		gr_conn_snat44_free_port(policy, fwd_key->proto, trans_port);
		return NULL; // connection pool exhausted
	}

	conn->nat = (struct nat44) {
		.orig_addr = fwd_key->src,
		.tran_addr = policy->replace,
		.orig_id = fwd_key->src_id,
		.tran_id = trans_port,
		.policy = policy,
	};

	return conn;
}

void gr_conn_snat44_free_port(struct snat44_policy *p, uint8_t proto, rte_be16_t port) {
	switch (proto) {
	case IPPROTO_TCP:
		gr_id_pool_put(p->tcp_ports, rte_be_to_cpu_16(port));
		break;
	case IPPROTO_UDP:
		gr_id_pool_put(p->udp_ports, rte_be_to_cpu_16(port));
		break;
	case IPPROTO_ICMP:
		gr_id_pool_put(p->icmp_ids, rte_be_to_cpu_16(port));
		break;
	}
}
