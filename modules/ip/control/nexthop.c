// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_iface.h>
#include <br_ip4.h>
#include <br_ip4_control.h>
#include <br_log.h>
#include <br_net_types.h>
#include <br_queue.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

struct nexthop *nh_array;
struct rte_hash *nh_hash;

struct nexthop_key {
	ip4_addr_t ip;
	// XXX: Using uint16_t to hold vrf_id causes the compiler to add 2 bytes
	// padding at the end of the structure. When the structure is
	// initialized on the stack, the padding bytes have undetermined
	// contents.
	//
	// This structure is used to compute a hash key. In order to get
	// deterministic results, use uint32_t to store the vrf_id so that the
	// compiler does not insert any padding.
	uint32_t vrf_id;
};

struct nexthop *ip4_nexthop_get(uint32_t idx) {
	return &nh_array[idx];
}

int ip4_nexthop_lookup(uint16_t vrf_id, ip4_addr_t ip, uint32_t *idx, struct nexthop **nh) {
	struct nexthop_key key = {ip, vrf_id};
	int32_t nh_idx;

	if ((nh_idx = rte_hash_lookup(nh_hash, &key)) < 0)
		return errno_set(-nh_idx);

	*idx = nh_idx;
	*nh = &nh_array[nh_idx];

	return 0;
}

int ip4_nexthop_add(uint16_t vrf_id, ip4_addr_t ip, uint32_t *idx, struct nexthop **nh) {
	struct nexthop_key key = {ip, vrf_id};
	int32_t nh_idx = rte_hash_add_key(nh_hash, &key);

	if (nh_idx < 0)
		return errno_set(-nh_idx);

	nh_array[nh_idx].vrf_id = vrf_id;
	nh_array[nh_idx].ip = ip;

	*idx = nh_idx;
	*nh = &nh_array[nh_idx];

	return 0;
}

void ip4_nexthop_decref(struct nexthop *nh) {
	if (nh->ref_count <= 1) {
		struct nexthop_key key = {nh->ip, nh->vrf_id};
		rte_hash_del_key(nh_hash, &key);
		memset(nh, 0, sizeof(*nh));
	} else {
		nh->ref_count--;
	}
}

void ip4_nexthop_incref(struct nexthop *nh) {
	nh->ref_count++;
}

static struct api_out nh4_add(const void *request, void **response) {
	const struct br_ip4_nh_add_req *req = request;
	struct nexthop *nh;
	uint32_t nh_idx;
	int ret;

	(void)response;

	if (req->nh.host == 0)
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if (ip4_nexthop_lookup(req->nh.vrf_id, req->nh.host, &nh_idx, &nh) == 0) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && br_eth_addr_eq(&req->nh.mac, (void *)&nh->lladdr))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((ret = ip4_nexthop_add(req->nh.vrf_id, req->nh.host, &nh_idx, &nh)) < 0)
		return api_out(-ret, 0);

	nh->iface_id = req->nh.iface_id;
	memcpy(&nh->lladdr, (void *)&req->nh.mac, sizeof(nh->lladdr));
	nh->flags = BR_IP4_NH_F_STATIC | BR_IP4_NH_F_REACHABLE;
	ret = ip4_route_insert(nh->vrf_id, nh->ip, 32, nh_idx, nh);

	return api_out(-ret, 0);
}

static struct api_out nh4_del(const void *request, void **response) {
	const struct br_ip4_nh_del_req *req = request;
	struct nexthop *nh;
	uint32_t idx;

	(void)response;

	if (req->vrf_id >= MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if (ip4_nexthop_lookup(req->vrf_id, req->host, &idx, &nh) < 0) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (BR_IP4_NH_F_LOCAL | BR_IP4_NH_F_LINK)) || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip4_nexthop_decref(), freeing the next hop
	if (ip4_route_delete(req->vrf_id, req->host, 32) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out nh4_list(const void *request, void **response) {
	const struct br_ip4_nh_list_req *req = request;
	struct br_ip4_nh_list_resp *resp = NULL;
	struct br_ip4_nh *api_nh;
	struct nexthop *nh;
	uint32_t num, iter;
	const void *key;
	int32_t idx;
	void *data;
	size_t len;

	num = 0;
	iter = 0;
	while ((idx = rte_hash_iterate(nh_hash, &key, &data, &iter)) >= 0) {
		nh = ip4_nexthop_get(idx);
		if (nh->vrf_id == req->vrf_id || req->vrf_id == UINT16_MAX)
			num++;
	}

	len = sizeof(*resp) + num * sizeof(struct br_ip4_nh);
	if ((resp = calloc(len, 1)) == NULL)
		return api_out(ENOMEM, 0);

	iter = 0;
	while ((idx = rte_hash_iterate(nh_hash, &key, &data, &iter)) >= 0) {
		nh = ip4_nexthop_get(idx);
		if (nh->vrf_id != req->vrf_id && req->vrf_id != UINT16_MAX)
			continue;
		api_nh = &resp->nhs[resp->n_nhs++];
		api_nh->host = nh->ip;
		api_nh->iface_id = nh->iface_id;
		api_nh->vrf_id = nh->vrf_id;
		memcpy(&api_nh->mac, &nh->lladdr, sizeof(api_nh->mac));
		api_nh->flags = nh->flags;
		if (nh->last_seen > 0)
			api_nh->age = (rte_get_tsc_cycles() - nh->last_seen) / rte_get_tsc_hz();
		api_nh->held_pkts = nh->held_pkts_num;
	}

	*response = resp;

	return api_out(0, len);
}

static void nh4_init(struct event_base *) {
	struct rte_hash_parameters params = {
		.name = "ip4_nh",
		.entries = MAX_NEXT_HOPS,
		.key_len = sizeof(struct nexthop_key),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
			| RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
	};
	nh_hash = rte_hash_create(&params);
	if (nh_hash == NULL)
		ABORT("rte_hash_create: %s", rte_strerror(rte_errno));

	nh_array = rte_calloc(
		"nh4_array",
		rte_hash_max_key_id(nh_hash) + 1,
		sizeof(struct nexthop),
		RTE_CACHE_LINE_SIZE
	);
	if (nh_array == NULL)
		ABORT("rte_calloc(nh4_array) failed");
}

static void nh4_fini(struct event_base *) {
	rte_hash_free(nh_hash);
	nh_hash = NULL;
	rte_free(nh_array);
	nh_array = NULL;
}

static struct br_api_handler nh4_add_handler = {
	.name = "ipv4 nexthop add",
	.request_type = BR_IP4_NH_ADD,
	.callback = nh4_add,
};
static struct br_api_handler nh4_del_handler = {
	.name = "ipv4 nexthop del",
	.request_type = BR_IP4_NH_DEL,
	.callback = nh4_del,
};
static struct br_api_handler nh4_list_handler = {
	.name = "ipv4 nexthop list",
	.request_type = BR_IP4_NH_LIST,
	.callback = nh4_list,
};

static struct br_module nh4_module = {
	.name = "ipv4 nexthop",
	.init = nh4_init,
	.fini = nh4_fini,
};

RTE_INIT(control_ip_init) {
	br_register_api_handler(&nh4_add_handler);
	br_register_api_handler(&nh4_del_handler);
	br_register_api_handler(&nh4_list_handler);
	br_register_module(&nh4_module);
}
