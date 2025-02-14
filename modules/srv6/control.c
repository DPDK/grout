// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Olivier Gournet

#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_srv6.h>
#include <gr_srv6_api.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>

#include <module.h>
#include <string.h>

// steer ////////////////////////////////////////////////////////////////

static struct rte_hash *srv6_steer_hash;

struct srv6_steer_data *srv6_steer_get(const struct nexthop *nh) {
	void *data;

	if (rte_hash_lookup_data(srv6_steer_hash, &nh, &data) < 0)
		return NULL;
	return data;
}

static struct srv6_steer_data *
srv6_steer_get_by_dest6(uint16_t vrf_id, const struct ip6_net *dest6) {
	struct nexthop *nh;
	void *data;

	nh = rib6_lookup_exact(vrf_id, GR_IFACE_ID_UNDEF, &dest6->ip, dest6->prefixlen);
	if (nh == NULL)
		return NULL;

	if (rte_hash_lookup_data(srv6_steer_hash, &nh, &data) < 0)
		return NULL;
	return data;
}

static struct srv6_steer_data *
srv6_steer_get_by_dest4(uint16_t vrf_id, const struct ip4_net *dest4) {
	struct nexthop *nh;
	void *data;

	nh = rib4_lookup_exact(vrf_id, dest4->ip, dest4->prefixlen);
	if (nh == NULL)
		return NULL;

	if (rte_hash_lookup_data(srv6_steer_hash, &nh, &data) < 0)
		return NULL;
	return data;
}

static struct api_out srv6_steer_add(const void *request, void ** /*response*/) {
	const struct gr_srv6_steer_add_req *req = request;
	struct srv6_steer_data *sd;
	struct nexthop *nh;
	int ret;

	// create nexthop
	// ipv4/v6 address on nexthop are not really useful, only for trace
	if (req->s.is_dest6) {
		sd = srv6_steer_get_by_dest6(req->s.vrf_id, &req->s.dest6);
		if (sd != NULL)
			return api_out(EEXIST, 0);

		nh = nh6_new(req->s.vrf_id, GR_IFACE_ID_UNDEF, &req->s.dest6.ip);
		if (nh == NULL)
			return api_out(errno, 0);
		nh->input_node = srv6_steer_v6_edge;
		nh->prefixlen = req->s.dest6.prefixlen;

		ret = rib6_insert(
			req->s.vrf_id,
			GR_IFACE_ID_UNDEF,
			&req->s.dest6.ip,
			req->s.dest6.prefixlen,
			nh
		);
		if (ret < 0)
			return api_out(ENOMEM, 0);

	} else {
		sd = srv6_steer_get_by_dest4(req->s.vrf_id, &req->s.dest4);
		if (sd != NULL)
			return api_out(EEXIST, 0);

		nh = nh4_new(req->s.vrf_id, GR_IFACE_ID_UNDEF, req->s.dest4.ip);
		if (nh == NULL)
			return api_out(errno, 0);
		nh->input_node = srv6_steer_v4_edge;
		nh->prefixlen = req->s.dest4.prefixlen;

		ret = rib4_insert(req->s.vrf_id, req->s.dest4.ip, req->s.dest4.prefixlen, nh);
		if (ret < 0)
			return api_out(ENOMEM, 0);
	}
	nh->flags |= GR_NH_F_GATEWAY | GR_NH_F_STATIC | GR_NH_F_REACHABLE;

	// create local steer data
	sd = calloc(1, sizeof(*sd) + sizeof(sd->nh[0]) * req->s.n_nh);
	if (sd == NULL)
		goto free_rib;
	sd->gr_nh = nexthop_incref(nh);
	sd->n_nh = req->s.n_nh;
	memcpy(sd->nh, req->s.nh, sizeof(sd->nh[0]) * req->s.n_nh);

	// index this data by nexthop
	ret = rte_hash_add_key_data(srv6_steer_hash, &sd->gr_nh, sd);
	if (ret < 0) {
		nexthop_decref(sd->gr_nh);
		free(sd);
		goto free_rib;
	}

	return api_out(0, 0);

free_rib:
	if (req->s.is_dest6)
		rib6_delete(
			req->s.vrf_id, GR_IFACE_ID_UNDEF, &req->s.dest6.ip, req->s.dest6.prefixlen
		);
	else
		rib4_delete(req->s.vrf_id, req->s.dest4.ip, req->s.dest4.prefixlen);
	return api_out(ENOMEM, 0);
}

static struct api_out srv6_steer_del(const void *request, void ** /*response*/) {
	const struct gr_srv6_steer_del_req *req = request;
	struct srv6_steer_data *sd;

	if (req->s.is_dest6) {
		sd = srv6_steer_get_by_dest6(req->s.vrf_id, &req->s.dest6);
		if (sd == NULL)
			return api_out(ENOENT, 0);

		rib6_delete(
			req->s.vrf_id, GR_IFACE_ID_UNDEF, &req->s.dest6.ip, req->s.dest6.prefixlen
		);

	} else {
		sd = srv6_steer_get_by_dest4(req->s.vrf_id, &req->s.dest4);
		if (sd == NULL)
			return api_out(ENOENT, 0);

		rib4_delete(req->s.vrf_id, req->s.dest4.ip, req->s.dest4.prefixlen);
	}

	rte_hash_del_key(srv6_steer_hash, &sd->gr_nh);
	nexthop_decref(sd->gr_nh);
	free(sd);

	return api_out(0, 0);
}

static struct api_out srv6_steer_list(const void *request, void **response) {
	const struct gr_srv6_steer_list_req *req = request;
	struct srv6_steer_data **sd_list = NULL;
	const struct nexthop **nh_list = NULL;
	struct gr_srv6_steer_list_resp *resp;
	const struct srv6_steer_data *sd;
	const struct nexthop *nh;
	struct gr_srv6_steer *psd;
	void *data_ptr, *ptr;
	const void *key_ptr;
	uint32_t iter, i;
	ssize_t len = 0;

	iter = 0;
	key_ptr = NULL;
	while (rte_hash_iterate(srv6_steer_hash, &key_ptr, &data_ptr, &iter) >= 0) {
		nh = *(const struct nexthop **)key_ptr;
		sd = data_ptr;
		if (req->vrf_id == UINT16_MAX || req->vrf_id == nh->vrf_id) {
			gr_vec_add(nh_list, nh);
			gr_vec_add(sd_list, data_ptr);
			len += sd->n_nh * sizeof(sd->nh[0]);
		}
	}
	len += sizeof(*resp) + sizeof(struct gr_srv6_steer) * gr_vec_len(sd_list);
	if ((resp = calloc(1, len)) == NULL)
		return api_out(ENOMEM, 0);

	if (sd_list == NULL) {
		*response = resp;
		return api_out(0, len);
	}

	resp->n_steer = gr_vec_len(sd_list);
	ptr = resp->steer;
	for (i = 0; i < resp->n_steer; i++) {
		psd = ptr;
		nh = nh_list[i];
		psd->vrf_id = nh->vrf_id;
		if (nh->family == AF_INET6) {
			psd->is_dest6 = true;
			psd->dest6.ip = nh->ipv6;
			psd->dest6.prefixlen = nh->prefixlen;
		} else {
			psd->is_dest6 = false;
			psd->dest4.ip = nh->ipv4;
			psd->dest4.prefixlen = nh->prefixlen;
		}
		psd->n_nh = sd_list[i]->n_nh;
		memcpy(psd->nh, sd_list[i]->nh, psd->n_nh * sizeof(psd->nh[0]));
		ptr += sizeof(*psd) + psd->n_nh * sizeof(psd->nh[0]);
	}
	assert(ptr - (void *)resp <= len);
	gr_vec_free(nh_list);
	gr_vec_free(sd_list);

	*response = resp;

	return api_out(0, len);
}

static void srv6_steer_init(void) {
	// store srv6 steering rules, index by nh (nexthop) ptr
	struct rte_hash_parameters params = {
		.name = "srv6_steer",
		.entries = 4096,
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
		free(data);
	}
	rte_hash_free(srv6_steer_hash);
	srv6_steer_hash = NULL;
}

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

	// create local nexthop for our localsid
	nh = nh6_new(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid);
	if (nh == NULL)
		return api_out(errno, 0);
	nh->input_node = srv6_local_edge;
	nh->flags |= GR_NH_F_STATIC | GR_NH_F_REACHABLE;

	// and add it to the routing table (/128), so ip6_input fib will
	// match this entry for srv6 pkt with DA == localsid, and will
	// follow nh->input_node => srv6_localsid
	r = rib6_insert(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128, nh);
	if (r < 0)
		return api_out(-r, 0);

	// init data for srv6 module
	data = calloc(1, sizeof(*data));
	if (data == NULL) {
		rib6_delete(req->l.vrf_id, GR_IFACE_ID_UNDEF, &req->l.lsid, 128);
		return api_out(ENOMEM, 0);
	}
	data->behavior = req->l.behavior;
	data->out_vrf_id = req->l.out_vrf_id;

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
	int r;

	r = rte_hash_del_key(srv6_localsid_hash, &key);
	if (r == -ENOENT)
		return api_out(ENOENT, 0);

	rib6_delete(req->vrf_id, GR_IFACE_ID_UNDEF, &req->lsid, 128);

	return api_out(-r, 0);
}

static struct api_out srv6_localsid_list(const void *request, void **response) {
	const struct gr_srv6_localsid_list_req *req = request;
	struct gr_srv6_localsid_list_resp *resp;
	const struct srv6_localsid_key *key;
	const struct srv6_localsid_data *data;
	struct gr_srv6_localsid *odata = NULL;
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

// srv6 module //////////////////////////////////////////////////////////

static void srv6_init(struct event_base *) {
	srv6_steer_init();
	srv6_localsid_init();
}

static void srv6_fini(struct event_base *) {
	srv6_steer_release();
	srv6_localsid_release();
}

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

static struct gr_module srv6_module = {
	.name = "srv6",
	.init = srv6_init,
	.fini = srv6_fini,
	.fini_prio = 1000,
};

RTE_INIT(srv6_constructor) {
	gr_register_api_handler(&srv6_steer_add_handler);
	gr_register_api_handler(&srv6_steer_del_handler);
	gr_register_api_handler(&srv6_steer_list_handler);
	gr_register_api_handler(&srv6_localsid_add_handler);
	gr_register_api_handler(&srv6_localsid_del_handler);
	gr_register_api_handler(&srv6_localsid_list_handler);
	gr_register_module(&srv6_module);
}
