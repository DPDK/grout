// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_log.h>
#include <gr_nh_control.h>
#include <gr_rcu.h>

#include <rte_malloc.h>

#include <stdint.h>

static bool group_equal(const struct nexthop *a, const struct nexthop *b) {
	const struct nexthop_info_group *da = nexthop_info_group(a);
	const struct nexthop_info_group *db = nexthop_info_group(b);

	if (da->n_members != db->n_members)
		return false;
	for (uint32_t i = 0; i < da->n_members; i++)
		if (da->members[i].nh != db->members[i].nh
		    || da->members[i].weight != db->members[i].weight)
			return false;
	return true;
}

static void group_free(struct nexthop *nh) {
	struct nexthop_info_group *pvt = nexthop_info_group(nh);

	for (uint32_t i = 0; i < pvt->n_members; i++)
		nexthop_decref(pvt->members[i].nh);
	rte_free(pvt->members);
	rte_free(pvt->reta);
}

static int order_by_weight_desc(const void *a, const void *b) {
	const struct nh_group_member *ma = a;
	const struct nh_group_member *mb = b;
	return mb->weight - ma->weight;
}

static int group_import_info(struct nexthop *nh, const void *info) {
	struct nexthop_info_group *pvt = nexthop_info_group(nh);
	const struct gr_nexthop_info_group *group = info;
	struct nh_group_member *members = NULL;
	struct nh_group_member *tmp = NULL;
	struct nexthop **old_reta = NULL;
	uint32_t min_weight, max_weight;
	struct nexthop **reta = NULL;
	uint32_t reta_size = 0;
	uint32_t n_tmp = 0;

	members = rte_zmalloc(
		__func__, group->n_members * sizeof(pvt->members[0]), RTE_CACHE_LINE_SIZE
	);
	if (group->n_members > 0 && members == NULL) {
		errno_set(ENOMEM);
		goto cleanup;
	}

	for (uint16_t i = 0; i < group->n_members; i++) {
		struct nexthop *nh = nexthop_lookup_id(group->members[i].nh_id);
		if (nh) {
			members[i].nh = nh;
			members[i].weight = group->members[i].weight;
		} else {
			errno = ENOENT;
			goto cleanup;
		}
	}

	if (group->n_members > 0) {
		// Order by desc weight: if we have too many nh in the nhg, the ones with
		// a higher weight will be included.
		qsort(members, group->n_members, sizeof(members[0]), order_by_weight_desc);

		max_weight = members[0].weight;
		min_weight = members[group->n_members - 1].weight;
		if (min_weight == 0)
			min_weight = 1;

		reta_size = (max_weight / min_weight) * group->n_members;
		if (reta_size > MAX_NH_GROUP_RETA_SIZE) {
			LOG(WARNING,
			    "nhg(%u) reta overflow (%u > %u)",
			    nh->nh_id,
			    reta_size,
			    MAX_NH_GROUP_RETA_SIZE);
			reta_size = MAX_NH_GROUP_RETA_SIZE;
		}
		reta_size = rte_align32pow2(reta_size);

		reta = rte_zmalloc(__func__, reta_size * sizeof(*reta), RTE_CACHE_LINE_SIZE);
		if (reta == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}

		for (uint16_t i = 0; i < group->n_members; i++)
			nexthop_incref(members[i].nh);

		// Fill the reta table with weighted distribution
		uint32_t total_weight = 0;
		for (uint16_t i = 0; i < group->n_members; i++)
			total_weight += members[i].weight;

		if (total_weight > 0) {
			uint32_t reta_idx = 0;
			uint32_t entries;

			for (uint16_t i = 0; i < group->n_members && reta_idx < reta_size; i++) {
				entries = (members[i].weight * reta_size + total_weight / 2)
					/ total_weight;

				if (entries == 0 && members[i].weight > 0)
					entries = 1;

				for (uint16_t j = 0; j < entries && reta_idx < reta_size; j++)
					reta[reta_idx++] = members[i].nh;
			}

			// Fill remaining entries with the first member if any slots left
			while (reta_idx < reta_size && group->n_members > 0)
				reta[reta_idx++] = members[0].nh;
		}
	}

	n_tmp = pvt->n_members;
	tmp = pvt->members;
	old_reta = pvt->reta;
	pvt->n_members = group->n_members;
	pvt->members = members;
	pvt->reta_size = reta_size;
	pvt->reta = reta;

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	for (uint32_t i = 0; i < n_tmp; i++)
		nexthop_decref(tmp[i].nh);

	rte_free(old_reta);
	rte_free(tmp);
	return 0;

cleanup:
	rte_free(tmp);
	rte_free(reta);
	rte_free(members);
	return errno_set(errno);
}

static struct gr_nexthop *group_to_api(const struct nexthop *nh, size_t *len) {
	const struct nexthop_info_group *group_priv = nexthop_info_group(nh);
	struct gr_nexthop_info_group *group_pub;
	struct gr_nexthop *pub;
	*len = sizeof(*pub) + sizeof(*group_pub)
		+ group_priv->n_members * sizeof(group_priv->members[0]);

	pub = malloc(*len);
	if (pub == NULL) {
		*len = 0;
		return errno_set_null(ENOMEM);
	}

	pub->base = nh->base;
	group_pub = (struct gr_nexthop_info_group *)pub->info;

	group_pub->n_members = group_priv->n_members;
	for (uint32_t i = 0; i < group_pub->n_members; i++) {
		group_pub->members[i].nh_id = group_priv->members[i].nh->nh_id;
		group_pub->members[i].weight = group_priv->members[i].weight;
	}

	return pub;
}

static struct nexthop_type_ops group_nh_ops = {
	.equal = group_equal,
	.free = group_free,
	.import_info = group_import_info,
	.to_api = group_to_api,
};

RTE_INIT(init) {
	nexthop_type_ops_register(GR_NH_T_GROUP, &group_nh_ops);
}
