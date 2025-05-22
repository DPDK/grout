// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include "srv6_priv.h"

#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_srv6.h>
#include <gr_vec.h>

static struct rte_hash *srv6_policy_hash;
static struct rte_hash *srv6_steer_hash;

// policies ////////////////////////////////////////////////////////////////

static struct srv6_policy_data *srv6_policy_get(const struct rte_ipv6_addr *bsid) {
	void *data;

	if (rte_hash_lookup_data(srv6_policy_hash, bsid, &data) < 0)
		return NULL;
	return data;
}

static struct api_out srv6_policy_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_policy_add_req *req = request;
	struct srv6_policy_data *d;
	int ret;

	if (req->p.n_seglist > GR_SRV6_POLICY_SEGLIST_COUNT_MAX)
		return api_out(EINVAL, 0);

	d = srv6_policy_get(&req->p.bsid);
	if (d != NULL)
		return api_out(EEXIST, 0);

	d = calloc(1, sizeof(*d) + sizeof(d->seglist[0]) * req->p.n_seglist);
	if (d == NULL)
		return api_out(ENOMEM, 0);
	d->bsid = req->p.bsid;
	d->encap = req->p.encap_behavior;
	d->weight = req->p.weight;
	d->n_seglist = req->p.n_seglist;
	memcpy(d->seglist, req->p.seglist, sizeof(d->seglist[0]) * req->p.n_seglist);

	ret = rte_hash_add_key_data(srv6_policy_hash, &req->p.bsid, d);
	if (ret < 0) {
		free(d);
		return api_out(ENOMEM, 0);
	}

	return api_out(0, 0);
}

static struct api_out srv6_policy_del(const void *request, void ** /*response*/) {
	const struct gr_srv6_policy_del_req *req = request;
	struct srv6_policy_data **dlist;
	struct srv6_policy_data *d;
	struct nexthop *nh;
	size_t i;

	d = srv6_policy_get(&req->bsid);
	if (d == NULL)
		return api_out(ENOENT, 0);

	gr_vec_foreach (nh, d->nhlist) {
		// remove this sr policy from nexthop's list of sr policy
		dlist = srv6_steer_get(nh);
		for (i = 0; i < gr_vec_len(dlist); i++) {
			if (dlist[i] == d) {
				gr_vec_del(dlist, i);
				break;
			}
		}
		// this steering rule doesn't have any output sr policy, remove it.
		if (gr_vec_len(dlist) == 0) {
			if (nh->type == GR_NH_SR6_IPV6)
				rib6_delete(
					nh->vrf_id, GR_IFACE_ID_UNDEF, &nh->ipv6, nh->prefixlen
				);
			else
				rib4_delete(nh->vrf_id, nh->ipv4, nh->prefixlen);
			rte_hash_del_key(srv6_steer_hash, &nh);
			gr_vec_free(dlist);
		}
		nexthop_decref(nh);
	}

	gr_vec_free(d->nhlist);
	free(d);
	rte_hash_del_key(srv6_policy_hash, &req->bsid);

	return api_out(0, 0);
}

static struct api_out srv6_policy_get_api(const void *request, void **response) {
	const struct gr_srv6_policy_get_req *req = request;
	struct gr_srv6_policy_get_resp *resp;
	struct srv6_policy_data *d;
	size_t len;

	d = srv6_policy_get(&req->bsid);
	if (d == NULL)
		return api_out(ENOENT, 0);

	len = sizeof(*resp) + sizeof(struct gr_srv6_policy) + d->n_seglist * sizeof(d->seglist[0]);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	resp->p.bsid = d->bsid;
	resp->p.weight = d->weight;
	resp->p.encap_behavior = d->encap;
	resp->p.n_seglist = d->n_seglist;
	memcpy(resp->p.seglist, d->seglist, d->n_seglist * sizeof(d->seglist[0]));

	*response = resp;
	return api_out(0, len);
}

static struct api_out srv6_policy_list(const void * /* request */, void **response) {
	struct srv6_policy_data **d_list = NULL;
	struct gr_srv6_policy_list_resp *resp;
	const struct srv6_policy_data *d;
	ssize_t len = sizeof(*resp);
	struct gr_srv6_policy *ad;
	void *data_ptr, *ptr;
	const void *key_ptr;
	uint32_t iter, i;

	iter = 0;
	key_ptr = NULL;
	while (rte_hash_iterate(srv6_policy_hash, &key_ptr, &data_ptr, &iter) >= 0) {
		d = data_ptr;
		gr_vec_add(d_list, data_ptr);
		len += sizeof(struct gr_srv6_policy) + d->n_seglist * sizeof(d->seglist[0]);
	}
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(d_list);
		return api_out(ENOMEM, 0);
	}

	if (d_list == NULL) {
		*response = resp;
		return api_out(0, len);
	}

	resp->n_policy = gr_vec_len(d_list);
	ptr = resp->policy;
	for (i = 0; i < resp->n_policy; i++) {
		d = d_list[i];
		ad = ptr;
		ad->bsid = d->bsid;
		ad->weight = d->weight;
		ad->encap_behavior = d->encap;
		ad->n_seglist = d->n_seglist;
		memcpy(ad->seglist, d->seglist, d->n_seglist * sizeof(d->seglist[0]));
		ptr += sizeof(*ad) + ad->n_seglist * sizeof(ad->seglist[0]);
	}
	assert(ptr - (void *)resp <= len);
	gr_vec_free(d_list);

	*response = resp;

	return api_out(0, len);
}

static void srv6_policy_init(void) {
	// store srv6 policying rules, index by binding-sid
	struct rte_hash_parameters params = {
		.name = "srv6_policy",
		.entries = 4096,
		.key_len = sizeof(struct rte_ipv6_addr),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	srv6_policy_hash = rte_hash_create(&params);
	if (srv6_policy_hash == NULL)
		ABORT("rte_hash_create(srv6_policy)");
}

static void srv6_policy_release(void) {
	struct srv6_policy_data *d;
	const void *key = NULL;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(srv6_policy_hash, &key, &data, &iter) >= 0) {
		rte_hash_del_key(srv6_policy_hash, key);
		d = data;
		gr_vec_free(d->nhlist);
		free(d);
	}
	rte_hash_free(srv6_policy_hash);
	srv6_policy_hash = NULL;
}

// steer ////////////////////////////////////////////////////////////////

struct srv6_policy_data **srv6_steer_get(const struct nexthop *nh) {
	void *data;

	if (nh == NULL || rte_hash_lookup_data(srv6_steer_hash, &nh, &data) < 0)
		return NULL;
	return data;
}

static struct api_out srv6_steer_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_steer_add_req *req = request;
	struct srv6_policy_data **dlist, **prev_dlist;
	struct srv6_policy_data *d, *d_tmp;
	struct nexthop *nh;

	d = srv6_policy_get(&req->bsid);
	if (d == NULL)
		return api_out(ENOENT, 0);

	// retrieve or create nexthop into rib4/rib6
	if (req->l3.is_dest6) {
		nh = rib6_lookup_exact(
			req->l3.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->l3.dest6.ip,
			req->l3.dest6.prefixlen
		);
		dlist = srv6_steer_get(nh);
		if (dlist != NULL)
			goto add_rule;

		nh = nexthop_new(
			GR_NH_SR6_IPV6, req->l3.vrf_id, GR_IFACE_ID_UNDEF, &req->l3.dest6.ip
		);
		if (nh == NULL)
			return api_out(errno, 0);
		nh->prefixlen = req->l3.dest6.prefixlen;

		if (rib6_insert(
			    req->l3.vrf_id,
			    GR_IFACE_ID_UNDEF,
			    &req->l3.dest6.ip,
			    req->l3.dest6.prefixlen,
			    GR_RT_ORIGIN_LINK,
			    nh
		    )
		    < 0)
			return api_out(errno, 0);

	} else {
		nh = rib4_lookup_exact(req->l3.vrf_id, req->l3.dest4.ip, req->l3.dest4.prefixlen);
		dlist = srv6_steer_get(nh);
		if (dlist != NULL)
			goto add_rule;

		nh = nexthop_new(
			GR_NH_SR6_IPV4, req->l3.vrf_id, GR_IFACE_ID_UNDEF, &req->l3.dest4.ip
		);
		if (nh == NULL)
			return api_out(errno, 0);
		nh->prefixlen = req->l3.dest4.prefixlen;

		if (rib4_insert(
			    req->l3.vrf_id,
			    req->l3.dest4.ip,
			    req->l3.dest4.prefixlen,
			    GR_RT_ORIGIN_LINK,
			    nh
		    )
		    < 0)
			return api_out(errno, 0);
	}
	nh->flags |= GR_NH_F_GATEWAY | GR_NH_F_STATIC | GR_NH_F_REACHABLE;

	// new nexthop: push this first policy
	gr_vec_add(dlist, d);
	if (rte_hash_add_key_data(srv6_steer_hash, &nh, dlist) < 0) {
		nexthop_decref(nh);
		if (req->l3.is_dest6)
			rib6_delete(
				req->l3.vrf_id,
				GR_IFACE_ID_UNDEF,
				&req->l3.dest6.ip,
				req->l3.dest6.prefixlen
			);
		else
			rib4_delete(req->l3.vrf_id, req->l3.dest4.ip, req->l3.dest4.prefixlen);
		return api_out(ENOMEM, 0);
	}

	gr_vec_add(d->nhlist, nh);
	return api_out(0, 0);

add_rule:
	// existing nexthop: check if not a duplicate, then add sr policy to nh
	gr_vec_foreach (d_tmp, dlist) {
		if (d_tmp == d)
			return api_out(EEXIST, 0);
	}
	nexthop_incref(nh);
	prev_dlist = dlist;
	gr_vec_add(dlist, d);
	if (prev_dlist != dlist)
		rte_hash_add_key_data(srv6_steer_hash, &nh, dlist);

	gr_vec_add(d->nhlist, nh);
	return api_out(0, 0);
}

static struct api_out srv6_steer_del(const void *request, void ** /*response*/) {
	const struct gr_srv6_steer_del_req *req = request;
	struct srv6_policy_data **dlist;
	struct srv6_policy_data *d;
	struct nexthop *nh;
	unsigned i;

	if (req->l3.is_dest6) {
		nh = rib6_lookup_exact(
			req->l3.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->l3.dest6.ip,
			req->l3.dest6.prefixlen
		);
		dlist = srv6_steer_get(nh);
		if (dlist == NULL)
			return api_out(ENOENT, 0);

		rib6_delete(
			req->l3.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->l3.dest6.ip,
			req->l3.dest6.prefixlen
		);

	} else {
		nh = rib4_lookup_exact(req->l3.vrf_id, req->l3.dest4.ip, req->l3.dest4.prefixlen);
		dlist = srv6_steer_get(nh);
		if (dlist == NULL)
			return api_out(ENOENT, 0);

		rib4_delete(req->l3.vrf_id, req->l3.dest4.ip, req->l3.dest4.prefixlen);
	}

	rte_hash_del_key(srv6_steer_hash, &nh);
	nexthop_decref(nh);

	gr_vec_foreach (d, dlist) {
		if (rte_ipv6_addr_is_unspec(&req->bsid) || rte_ipv6_addr_eq(&req->bsid, &d->bsid)) {
			for (i = 0; i < gr_vec_len(d->nhlist); i++) {
				if (nh == d->nhlist[i]) {
					gr_vec_del(d->nhlist, i);
					break;
				}
			}
		}
	}
	gr_vec_free(dlist);

	return api_out(0, 0);
}

static struct api_out srv6_steer_list(const void *request, void **response) {
	const struct gr_srv6_steer_list_req *req = request;
	struct srv6_policy_data ***d_listlist = NULL;
	const struct nexthop **nh_list = NULL;
	struct gr_srv6_steer_list_resp *resp;
	struct srv6_policy_data **d_list;
	ssize_t j, len = sizeof(*resp);
	struct gr_srv6_steer_entry *e;
	const struct nexthop *nh;
	void *data_ptr, *ptr;
	const void *key_ptr;
	uint32_t iter, i;

	iter = 0;
	key_ptr = NULL;
	while (rte_hash_iterate(srv6_steer_hash, &key_ptr, &data_ptr, &iter) >= 0) {
		nh = *(const struct nexthop **)key_ptr;
		d_list = data_ptr;
		if (req->vrf_id == UINT16_MAX || req->vrf_id == nh->vrf_id) {
			gr_vec_add(nh_list, nh);
			gr_vec_add(d_listlist, data_ptr);
			len += sizeof(struct gr_srv6_steer_entry
			       ) + gr_vec_len(d_list) * sizeof(struct rte_ipv6_addr);
		}
	}
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(nh_list);
		gr_vec_free(d_listlist);
		return api_out(ENOMEM, 0);
	}

	if (nh_list == NULL) {
		*response = resp;
		return api_out(0, len);
	}

	resp->n_steer = gr_vec_len(nh_list);
	ptr = resp->steer;
	for (i = 0; i < resp->n_steer; i++) {
		e = ptr;
		nh = nh_list[i];
		e->l3.vrf_id = nh->vrf_id;
		if (nh->type == GR_NH_SR6_IPV6) {
			e->l3.is_dest6 = true;
			e->l3.dest6.ip = nh->ipv6;
			e->l3.dest6.prefixlen = nh->prefixlen;
		} else if (nh->type == GR_NH_SR6_IPV4) {
			e->l3.is_dest6 = false;
			e->l3.dest4.ip = nh->ipv4;
			e->l3.dest4.prefixlen = nh->prefixlen;
		} else
			abort();
		d_list = d_listlist[i];
		e->n_bsid = gr_vec_len(d_list);
		for (j = 0; j < e->n_bsid; j++)
			e->bsid[j] = d_list[j]->bsid;
		ptr += sizeof(*e) + e->n_bsid * sizeof(e->bsid[0]);
	}
	assert(ptr - (void *)resp <= len);
	gr_vec_free(nh_list);
	gr_vec_free(d_listlist);

	*response = resp;

	return api_out(0, len);
}

static void srv6_steer_init(void) {
	// store srv6 steering rules, index by nh (nexthop) ptr
	struct rte_hash_parameters params = {
		.name = "srv6_steer",
		.entries = 8192,
		.key_len = sizeof(struct nexthop *),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	srv6_steer_hash = rte_hash_create(&params);
	if (srv6_steer_hash == NULL)
		ABORT("rte_hash_create(srv6_steer)");
}

static void srv6_steer_release(void) {
	const void *key = NULL;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(srv6_steer_hash, &key, &data, &iter) >= 0) {
		rte_hash_del_key(srv6_steer_hash, key);
		gr_vec_free(data);
	}

	rte_hash_free(srv6_steer_hash);
	srv6_steer_hash = NULL;
}

// srv6 headend module /////////////////////////////////////////////////////

static void srv6_init(struct event_base *) {
	srv6_policy_init();
	srv6_steer_init();
}

static void srv6_fini(struct event_base *) {
	srv6_policy_release();
	srv6_steer_release();
}

static struct gr_api_handler srv6_policy_add_handler = {
	.name = "sr policy add",
	.request_type = GR_SRV6_POLICY_ADD,
	.callback = srv6_policy_add,
};
static struct gr_api_handler srv6_policy_del_handler = {
	.name = "sr policy del",
	.request_type = GR_SRV6_POLICY_DEL,
	.callback = srv6_policy_del,
};
static struct gr_api_handler srv6_policy_get_handler = {
	.name = "sr policy get",
	.request_type = GR_SRV6_POLICY_GET,
	.callback = srv6_policy_get_api,
};
static struct gr_api_handler srv6_policy_list_handler = {
	.name = "sr policy list",
	.request_type = GR_SRV6_POLICY_LIST,
	.callback = srv6_policy_list,
};

static struct gr_api_handler srv6_steer_add_handler = {
	.name = "sr steer add",
	.request_type = GR_SRV6_STEER_ADD,
	.callback = srv6_steer_add,
};
static struct gr_api_handler srv6_steer_del_handler = {
	.name = "sr steer del",
	.request_type = GR_SRV6_STEER_DEL,
	.callback = srv6_steer_del,
};
static struct gr_api_handler srv6_steer_list_handler = {
	.name = "sr steer list",
	.request_type = GR_SRV6_STEER_LIST,
	.callback = srv6_steer_list,
};

static struct gr_module srv6_headend_module = {
	.name = "srv6_headend",
	.init = srv6_init,
	.fini = srv6_fini,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_policy_add_handler);
	gr_register_api_handler(&srv6_policy_del_handler);
	gr_register_api_handler(&srv6_policy_get_handler);
	gr_register_api_handler(&srv6_policy_list_handler);
	gr_register_api_handler(&srv6_steer_add_handler);
	gr_register_api_handler(&srv6_steer_del_handler);
	gr_register_api_handler(&srv6_steer_list_handler);
	gr_register_module(&srv6_headend_module);
}
