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

static struct rte_hash *srv6_encap_hash;

// routes ////////////////////////////////////////////////////////////////

static struct srv6_encap_data *srv6_encap_get(const struct nexthop *nh) {
	void *data;

	if (nh == NULL || rte_hash_lookup_data(srv6_encap_hash, &nh, &data) < 0)
		return NULL;

	return data;
}

static int srv6_encap_data_add(
	struct nexthop *nh,
	gr_srv6_encap_behavior_t encap_behavior,
	uint8_t n_seglist,
	const struct rte_ipv6_addr *seglist,
	struct srv6_encap_data **d
) {
	struct srv6_encap_data *_d;
	int ret;

	if (srv6_encap_get(nh))
		return -EEXIST;

	_d = calloc(1, sizeof(*_d) + sizeof(_d->seglist[0]) * n_seglist);
	if (_d == NULL)
		return -ENOMEM;

	_d->encap = encap_behavior;
	_d->n_seglist = n_seglist;
	memcpy(_d->seglist, seglist, sizeof(_d->seglist[0]) * n_seglist);

	ret = rte_hash_add_key_data(srv6_encap_hash, &nh, _d);
	if (ret < 0) {
		free(_d);
		return -EEXIST;
	}

	nexthop_incref(nh);
	*d = _d;
	return 0;
}

static int srv6_encap_data_del(struct nexthop *nh, struct srv6_encap_data *d) {
	rte_hash_del_key(srv6_encap_hash, &nh);
	nexthop_decref(nh);
	free(d);
	return 0;
}

static void srv6_encap_data_init(void) {
	// store srv6 encap data, index by nh
	struct rte_hash_parameters params = {
		.name = "srv6_encap",
		.entries = 4096,
		.key_len = sizeof(struct nexthop *),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	srv6_encap_hash = rte_hash_create(&params);
	if (srv6_encap_hash == NULL)
		ABORT("rte_hash_create(srv6_encap)");
}

static void srv6_encap_data_release(void) {
	const void *key = NULL;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(srv6_encap_hash, &key, &data, &iter) >= 0) {
		srv6_encap_data_del((struct nexthop *)key, (struct srv6_encap_data *)data);
	}
	rte_hash_free(srv6_encap_hash);
	srv6_encap_hash = NULL;
}

struct srv6_encap_data *srv6_encap_data_get(const struct nexthop *nh) {
	void *data;

	if (nh == NULL || nh->type != GR_NH_T_SR6
	    || rte_hash_lookup_data(srv6_encap_hash, &nh, &data) < 0)
		return NULL;
	return data;
}

// srv6 route ////////////////////////////////////////////////////////////////
static struct api_out srv6_route_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_route_add_req *req = request;
	struct srv6_encap_data *d;
	struct nexthop *nh;
	int ret;

	// retrieve or create nexthop into rib4/rib6
	if (req->r.key.is_dest6) {
		nh = rib6_lookup_exact(
			req->r.key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->r.key.dest6.ip,
			req->r.key.dest6.prefixlen
		);

		d = srv6_encap_data_get(nh);
		if (d != NULL)
			return api_out(EEXIST, 0);

		nh = nexthop_new(
			GR_AF_IP6, req->r.key.vrf_id, GR_IFACE_ID_UNDEF, &req->r.key.dest6.ip
		);
		if (nh == NULL)
			return api_out(errno, 0);

		nh->prefixlen = req->r.key.dest6.prefixlen;
	} else {
		nh = rib4_lookup_exact(
			req->r.key.vrf_id, req->r.key.dest4.ip, req->r.key.dest4.prefixlen
		);
		d = srv6_encap_data_get(nh);
		if (d != NULL)
			return api_out(EEXIST, 0);

		nh = nexthop_new(
			GR_AF_IP4, req->r.key.vrf_id, GR_IFACE_ID_UNDEF, &req->r.key.dest4.ip
		);
		if (nh == NULL)
			return api_out(errno, 0);
		nh->prefixlen = req->r.key.dest4.prefixlen;
	}
	nh->type = GR_NH_T_SR6;
	nh->flags |= GR_NH_F_GATEWAY | GR_NH_F_STATIC;
	nh->state = GR_NH_S_REACHABLE;

	ret = srv6_encap_data_add(nh, req->r.encap_behavior, req->r.n_seglist, req->r.seglist, &d);
	if (ret < 0) {
		nexthop_decref(nh);
		return api_out(-ret, 0);
	}

	if (req->r.key.is_dest6)
		ret = rib6_insert(
			req->r.key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->r.key.dest6.ip,
			req->r.key.dest6.prefixlen,
			GR_RT_ORIGIN_LINK,
			nh
		);
	else
		ret = rib4_insert(
			req->r.key.vrf_id,
			req->r.key.dest4.ip,
			req->r.key.dest4.prefixlen,
			GR_RT_ORIGIN_LINK,
			nh
		);

	if (ret < 0) {
		srv6_encap_data_del(nh, d);
		return api_out(-ret, 0);
	}

	return api_out(0, 0);
}

static struct api_out srv6_route_del(const void *request, void ** /*response*/) {
	const struct gr_srv6_route_del_req *req = request;
	struct srv6_encap_data *d;
	struct nexthop *nh;

	if (req->key.is_dest6)
		nh = rib6_lookup_exact(
			req->key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->key.dest6.ip,
			req->key.dest6.prefixlen
		);
	else
		nh = rib4_lookup_exact(
			req->key.vrf_id, req->key.dest4.ip, req->key.dest4.prefixlen
		);

	d = srv6_encap_data_get(nh);
	if (d != NULL)
		return api_out(EEXIST, 0);

	if (req->key.is_dest6)
		rib6_delete(
			req->key.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->key.dest6.ip,
			req->key.dest6.prefixlen
		);

	else
		rib4_delete(req->key.vrf_id, req->key.dest4.ip, req->key.dest4.prefixlen);

	srv6_encap_data_del(nh, d);
	return api_out(0, 0);
}

static struct api_out srv6_route_list(const void *request, void **response) {
	const struct gr_srv6_route_list_req *req = request;

	struct srv6_encap_data **d_list = NULL;
	const struct nexthop **nh_list = NULL;
	struct gr_srv6_route_list_resp *resp;
	struct srv6_encap_data *d;
	ssize_t len = sizeof(*resp);
	struct gr_srv6_route *r;
	const struct nexthop *nh;
	void *data_ptr, *ptr;
	const void *key_ptr;
	uint32_t iter, i;

	iter = 0;
	key_ptr = NULL;
	while (rte_hash_iterate(srv6_encap_hash, &key_ptr, &data_ptr, &iter) >= 0) {
		nh = *(const struct nexthop **)key_ptr;
		d = data_ptr;

		if (req->vrf_id == UINT16_MAX || req->vrf_id == nh->vrf_id) {
			gr_vec_add(nh_list, nh);
			gr_vec_add(d_list, d);
			len += sizeof(struct gr_srv6_route) + d->n_seglist * sizeof(d->seglist[0]);
		}
	}
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(nh_list);
		gr_vec_free(d_list);
		return api_out(ENOMEM, 0);
	}

	if (nh_list == NULL) {
		*response = resp;
		return api_out(0, len);
	}

	resp->n_route = gr_vec_len(nh_list);
	ptr = resp->route;
	for (i = 0; i < resp->n_route; i++) {
		r = ptr;
		nh = nh_list[i];
		d = d_list[i];

		r->key.vrf_id = nh->vrf_id;
		switch (nh->af) {
		case GR_AF_IP6:
			r->key.is_dest6 = true;
			r->key.dest6.ip = nh->ipv6;
			r->key.dest6.prefixlen = nh->prefixlen;
			break;
		case GR_AF_IP4:
			r->key.is_dest6 = false;
			r->key.dest4.ip = nh->ipv4;
			r->key.dest4.prefixlen = nh->prefixlen;
			break;
		default:
			abort();
		}

		r->encap_behavior = d->encap;
		r->n_seglist = d->n_seglist;
		memcpy(r->seglist, d->seglist, r->n_seglist * sizeof(r->seglist[0]));
		ptr += sizeof(*r) + r->n_seglist * sizeof(r->seglist[0]);
	}
	assert(ptr - (void *)resp <= len);
	gr_vec_free(nh_list);
	gr_vec_free(d_list);

	*response = resp;

	return api_out(0, len);
}

// srv6 headend module /////////////////////////////////////////////////////

static void srv6_init(struct event_base *) {
	srv6_encap_data_init();
}

static void srv6_fini(struct event_base *) {
	srv6_encap_data_release();
}

static struct gr_api_handler srv6_route_add_handler = {
	.name = "sr route add",
	.request_type = GR_SRV6_ROUTE_ADD,
	.callback = srv6_route_add,
};
static struct gr_api_handler srv6_route_del_handler = {
	.name = "sr route del",
	.request_type = GR_SRV6_ROUTE_DEL,
	.callback = srv6_route_del,
};
static struct gr_api_handler srv6_route_list_handler = {
	.name = "sr route list",
	.request_type = GR_SRV6_ROUTE_LIST,
	.callback = srv6_route_list,
};

static struct gr_module srv6_headend_module = {
	.name = "srv6_headend",
	.init = srv6_init,
	.fini = srv6_fini,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_route_add_handler);
	gr_register_api_handler(&srv6_route_del_handler);
	gr_register_api_handler(&srv6_route_list_handler);
	gr_register_module(&srv6_headend_module);
}
