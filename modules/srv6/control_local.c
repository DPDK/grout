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

// localsid /////////////////////////////////////////////////////////////

struct srv6_localsid_key {
	struct rte_ipv6_addr lsid;
	uint32_t vrf_id;
};

static struct rte_hash *srv6_localsid_hash;

struct srv6_localsid_data *srv6_localsid_get(const struct rte_ipv6_addr *lsid, uint16_t vrf_id) {
	struct srv6_localsid_key key = {*lsid, vrf_id};
	void *data;

	if (rte_hash_lookup_data(srv6_localsid_hash, &key, &data) < 0)
		return NULL;
	return data;
}

static struct api_out srv6_localsid_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_localsid_add_req *req = request;
	struct srv6_localsid_key key = {req->l.lsid, req->l.vrf_id};
	struct srv6_localsid_data *data;
	struct nexthop *nh;
	int r;

	nh = nexthop_new(GR_NH_SR6_IPV6, req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid);
	if (nh == NULL)
		return api_out(errno, 0);
	nh->flags |= GR_NH_F_LOCAL | GR_NH_F_STATIC | GR_NH_F_REACHABLE;

	r = rib6_insert(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128, nh);
	if (r < 0)
		return api_out(-r, 0);

	if ((data = calloc(1, sizeof(*data))) == NULL) {
		rib6_delete(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128);
		return api_out(ENOMEM, 0);
	}
	data->behavior = req->l.behavior;
	data->out_vrf_id = req->l.out_vrf_id;
	data->flags = req->l.flags;

	if (rte_hash_add_key_data(srv6_localsid_hash, &key, data) < 0) {
		rib6_delete(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128);
		free(data);
		return api_out(ENOMEM, 0);
	}

	return api_out(0, 0);
}

static struct api_out srv6_localsid_del(const void *request, void ** /*response*/) {
	const struct gr_srv6_localsid_del_req *req = request;
	struct srv6_localsid_key key = {req->lsid, req->vrf_id};
	struct srv6_localsid_data *d;

	d = srv6_localsid_get(&req->lsid, req->vrf_id);
	if (d == NULL)
		api_out(ENOENT, 0);

	free(d);
	rte_hash_del_key(srv6_localsid_hash, &key);
	rib6_delete(req->vrf_id, GR_IFACE_ID_UNDEF, &req->lsid, 128);

	return api_out(0, 0);
}

static struct api_out srv6_localsid_list(const void *request, void **response) {
	const struct gr_srv6_localsid_list_req *req = request;
	struct gr_srv6_localsid_list_resp *resp;
	const struct srv6_localsid_data *data;
	struct gr_srv6_localsid *odata = NULL;
	const struct srv6_localsid_key *key;
	struct gr_srv6_localsid ldata;
	size_t len = sizeof(*resp);
	const void *key_ptr;
	void *data_ptr;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(srv6_localsid_hash, &key_ptr, &data_ptr, &iter) >= 0) {
		key = key_ptr;
		data = data_ptr;
		if (req->vrf_id == UINT16_MAX || req->vrf_id == key->vrf_id) {
			memset(&ldata, 0x00, sizeof(ldata));
			ldata.lsid = key->lsid;
			ldata.vrf_id = key->vrf_id;
			ldata.behavior = data->behavior;
			ldata.flags = data->flags;
			ldata.out_vrf_id = data->out_vrf_id;
			gr_vec_add(odata, ldata);
			len += sizeof(ldata);
		}
	}
	if ((resp = calloc(1, len)) == NULL) {
		gr_vec_free(odata);
		return api_out(ENOMEM, 0);
	}
	resp->n_lsid = gr_vec_len(odata);
	if (resp->n_lsid)
		memcpy(resp->lsid, odata, resp->n_lsid * sizeof(ldata));
	gr_vec_free(odata);

	*response = resp;
	return api_out(0, len);
}

static void srv6_localsid_init(void) {
	struct rte_hash_parameters params = {
		.name = "srv6_localsid",
		.entries = 1024,
		.key_len = sizeof(struct srv6_localsid_key),
		.socket_id = SOCKET_ID_ANY,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	srv6_localsid_hash = rte_hash_create(&params);
	if (srv6_localsid_hash == NULL)
		ABORT("rte_hash_create(srv6_localsid)");
}

static void srv6_localsid_release(void) {
	const void *key = NULL;
	void *data = NULL;
	uint32_t iter;

	iter = 0;
	while (rte_hash_iterate(srv6_localsid_hash, &key, &data, &iter) >= 0) {
		rte_hash_del_key(srv6_localsid_hash, key);
		free(data);
	}
	rte_hash_free(srv6_localsid_hash);
	srv6_localsid_hash = NULL;
}

// srv6 localsid module //////////////////////////////////////////////////////

static void srv6_init(struct event_base *) {
	srv6_localsid_init();
}

static void srv6_fini(struct event_base *) {
	srv6_localsid_release();
}

static struct gr_api_handler srv6_localsid_add_handler = {
	.name = "sr localsid add",
	.request_type = GR_SRV6_LOCALSID_ADD,
	.callback = srv6_localsid_add,
};
static struct gr_api_handler srv6_localsid_del_handler = {
	.name = "sr localsid del",
	.request_type = GR_SRV6_LOCALSID_DEL,
	.callback = srv6_localsid_del,
};
static struct gr_api_handler srv6_localsid_list_handler = {
	.name = "sr localsid list",
	.request_type = GR_SRV6_LOCALSID_LIST,
	.callback = srv6_localsid_list,
};

static struct gr_module srv6_local_module = {
	.name = "srv6_local",
	.init = srv6_init,
	.fini = srv6_fini,
	.fini_prio = 1000,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_localsid_add_handler);
	gr_register_api_handler(&srv6_localsid_del_handler);
	gr_register_api_handler(&srv6_localsid_list_handler);
	gr_register_module(&srv6_local_module);
}
