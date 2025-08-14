// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_conntrack.h>
#include <gr_nat_control.h>
#include <gr_vec.h>

#include <rte_malloc.h>

#include <stdint.h>

static uint16_t n_policies;
static struct gr_snat44_policy *policies;

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
