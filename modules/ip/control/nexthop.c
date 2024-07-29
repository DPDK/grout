// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_control.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_net_types.h>
#include <gr_queue.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct nexthop *nh_array;
static struct rte_hash *nh_hash;

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

		rte_spinlock_lock(&nh->lock);
		// Flush all held packets.
		struct rte_mbuf *m = nh->held_pkts_head;
		while (m != NULL) {
			struct rte_mbuf *next = queue_mbuf_data(m)->next;
			rte_pktmbuf_free(m);
			m = next;
		}
		rte_spinlock_unlock(&nh->lock);

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
	const struct gr_ip4_nh_add_req *req = request;
	struct nexthop *nh;
	uint32_t nh_idx;
	int ret;

	(void)response;

	if (req->nh.host == 0)
		return api_out(EINVAL, 0);
	if (req->nh.vrf_id >= IP4_MAX_VRFS)
		return api_out(EOVERFLOW, 0);
	if (iface_from_id(req->nh.iface_id) == NULL)
		return api_out(errno, 0);

	if (ip4_nexthop_lookup(req->nh.vrf_id, req->nh.host, &nh_idx, &nh) == 0) {
		if (req->exist_ok && req->nh.iface_id == nh->iface_id
		    && rte_is_same_ether_addr(&req->nh.mac, (void *)&nh->lladdr))
			return api_out(0, 0);
		return api_out(EEXIST, 0);
	}

	if ((ret = ip4_nexthop_add(req->nh.vrf_id, req->nh.host, &nh_idx, &nh)) < 0)
		return api_out(-ret, 0);

	nh->iface_id = req->nh.iface_id;
	memcpy(&nh->lladdr, (void *)&req->nh.mac, sizeof(nh->lladdr));
	nh->flags = GR_IP4_NH_F_STATIC | GR_IP4_NH_F_REACHABLE;
	ret = ip4_route_insert(nh->vrf_id, nh->ip, 32, nh_idx, nh);

	return api_out(-ret, 0);
}

static struct api_out nh4_del(const void *request, void **response) {
	const struct gr_ip4_nh_del_req *req = request;
	struct nexthop *nh;
	uint32_t idx;

	(void)response;

	if (req->vrf_id >= IP4_MAX_VRFS)
		return api_out(EOVERFLOW, 0);

	if (ip4_nexthop_lookup(req->vrf_id, req->host, &idx, &nh) < 0) {
		if (errno == ENOENT && req->missing_ok)
			return api_out(0, 0);
		return api_out(errno, 0);
	}
	if ((nh->flags & (GR_IP4_NH_F_LOCAL | GR_IP4_NH_F_LINK | GR_IP4_NH_F_GATEWAY))
	    || nh->ref_count > 1)
		return api_out(EBUSY, 0);

	// this also does ip4_nexthop_decref(), freeing the next hop
	if (ip4_route_delete(req->vrf_id, req->host, 32) < 0)
		return api_out(errno, 0);

	return api_out(0, 0);
}

static struct api_out nh4_list(const void *request, void **response) {
	const struct gr_ip4_nh_list_req *req = request;
	struct gr_ip4_nh_list_resp *resp = NULL;
	struct gr_ip4_nh *api_nh;
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

	len = sizeof(*resp) + num * sizeof(struct gr_ip4_nh);
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
		if (nh->last_reply > 0)
			api_nh->age = (rte_get_tsc_cycles() - nh->last_reply) / rte_get_tsc_hz();
		api_nh->held_pkts = nh->held_pkts_num;
	}

	*response = resp;

	return api_out(0, len);
}

static void nexthop_gc(evutil_socket_t, short, void *) {
	uint64_t now = rte_get_tsc_cycles();
	uint64_t reply_age, request_age;
	unsigned probes, max_probes;
	char buf[INET_ADDRSTRLEN];
	struct nexthop *nh;
	const void *key;
	uint32_t iter;
	int32_t idx;
	void *data;

	max_probes = IP4_NH_UCAST_PROBES + IP4_NH_BCAST_PROBES;
	iter = 0;

	while ((idx = rte_hash_iterate(nh_hash, &key, &data, &iter)) >= 0) {
		nh = ip4_nexthop_get(idx);

		if (nh->flags & GR_IP4_NH_F_STATIC)
			continue;

		reply_age = (now - nh->last_reply) / rte_get_tsc_hz();
		request_age = (now - nh->last_request) / rte_get_tsc_hz();
		probes = nh->ucast_probes + nh->bcast_probes;

		if (nh->flags & (GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE) && request_age > probes) {
			if (probes >= max_probes && !(nh->flags & GR_IP4_NH_F_GATEWAY)) {
				inet_ntop(AF_INET, &nh->ip, buf, sizeof(buf));
				LOG(DEBUG,
				    "%s vrf=%u failed_probes=%u held_pkts=%u: %s -> failed",
				    buf,
				    nh->vrf_id,
				    probes,
				    nh->held_pkts_num,
				    gr_ip4_nh_f_name(
					    nh->flags & (GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE)
				    ));
				nh->flags &= ~(GR_IP4_NH_F_PENDING | GR_IP4_NH_F_STALE);
				nh->flags |= GR_IP4_NH_F_FAILED;
			} else {
				if (arp_output_request_solicit(nh) < 0)
					LOG(ERR, "arp_output_request_solicit: %s", strerror(errno));
			}
		} else if (nh->flags & GR_IP4_NH_F_REACHABLE
			   && reply_age > IP4_NH_LIFETIME_REACHABLE) {
			nh->flags &= ~GR_IP4_NH_F_REACHABLE;
			nh->flags |= GR_IP4_NH_F_STALE;
		} else if (nh->flags & GR_IP4_NH_F_FAILED
			   && request_age > IP4_NH_LIFETIME_UNREACHABLE) {
			inet_ntop(AF_INET, &nh->ip, buf, sizeof(buf));
			LOG(DEBUG,
			    "%s vrf=%u failed_probes=%u held_pkts=%u: failed -> <destroy>",
			    buf,
			    nh->vrf_id,
			    probes,
			    nh->held_pkts_num);

			// this also does ip4_nexthop_decref(), freeing the next hop
			// and buffered packets.
			if (ip4_route_delete(nh->vrf_id, nh->ip, 32) < 0)
				LOG(ERR, "ip4_route_delete: %s", strerror(errno));
		}
	}
}

static struct event *nh_gc_timer;

static void nh4_init(struct event_base *ev_base) {
	struct rte_hash_parameters params = {
		.name = "ip4_nh",
		.entries = IP4_MAX_NEXT_HOPS,
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

	nh_gc_timer = event_new(ev_base, -1, EV_PERSIST | EV_FINALIZE, nexthop_gc, NULL);
	if (nh_gc_timer == NULL)
		ABORT("event_new() failed");
	struct timeval tv = {.tv_sec = 1};
	if (event_add(nh_gc_timer, &tv) < 0)
		ABORT("event_add() failed");
}

static void nh4_fini(struct event_base *) {
	event_free(nh_gc_timer);
	nh_gc_timer = NULL;
	rte_hash_free(nh_hash);
	nh_hash = NULL;
	rte_free(nh_array);
	nh_array = NULL;
}

static struct gr_api_handler nh4_add_handler = {
	.name = "ipv4 nexthop add",
	.request_type = GR_IP4_NH_ADD,
	.callback = nh4_add,
};
static struct gr_api_handler nh4_del_handler = {
	.name = "ipv4 nexthop del",
	.request_type = GR_IP4_NH_DEL,
	.callback = nh4_del,
};
static struct gr_api_handler nh4_list_handler = {
	.name = "ipv4 nexthop list",
	.request_type = GR_IP4_NH_LIST,
	.callback = nh4_list,
};

static struct gr_module nh4_module = {
	.name = "ipv4 nexthop",
	.init = nh4_init,
	.fini = nh4_fini,
	.fini_prio = 20000,
};

RTE_INIT(control_ip_init) {
	gr_register_api_handler(&nh4_add_handler);
	gr_register_api_handler(&nh4_del_handler);
	gr_register_api_handler(&nh4_list_handler);
	gr_register_module(&nh4_module);
}
