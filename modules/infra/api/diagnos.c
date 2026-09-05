// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#include "module.h"

#include <gr_api.h>
#include <gr_infra.h>

#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_graph.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf_dyn.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_tailq.h>
#include <rte_trace.h>

static void graph_dump(FILE *f, struct rte_graph *graph) {
	rte_graph_obj_dump(f, graph, true);
}

static void malloc_dump_stats(FILE *f) {
	rte_malloc_dump_stats(f, NULL);
}

static void node_dump(FILE *f, void *id) {
	rte_node_dump(f, (rte_node_t)(uintptr_t)id);
}

static void *node_from_name(const char *name) {
	rte_node_t id = rte_node_from_name(name);
	return id != RTE_NODE_ID_INVALID ? (void *)(uintptr_t)id : NULL;
}

typedef void (*dump_list_fn_t)(FILE *f);
typedef void (*dump_fn_t)(FILE *f, void *obj);
typedef void *(*lookup_fn_t)(const char *name);

static const struct obj_dump_helper {
	char *type;
	dump_list_fn_t dump_list_fn;
	dump_fn_t dump_fn;
	lookup_fn_t lookup_fn;
} obj_dump_helpers[] = {
	// DPDK libs, in alphabetical order.
	{"bus", rte_bus_dump, NULL, (lookup_fn_t)rte_bus_find_by_name},
	{"graph", rte_graph_list_dump, (dump_fn_t)graph_dump, (lookup_fn_t)rte_graph_lookup},
	{"lcore", rte_lcore_dump, NULL, NULL},
	{"log", rte_log_dump, NULL, NULL},
	{"malloc_heaps", rte_malloc_dump_heaps, NULL, NULL},
	{"malloc_stats", malloc_dump_stats, NULL, NULL},
	{"mbuf_dyn", rte_mbuf_dyn_dump, NULL, NULL},
	{"mempool",
	 rte_mempool_list_dump,
	 (dump_fn_t)rte_mempool_dump,
	 (lookup_fn_t)rte_mempool_lookup},
	{"memzone", rte_memzone_dump, NULL, NULL},
	{"node", rte_node_list_dump, node_dump, node_from_name},
	{"pci", rte_pci_dump, NULL, NULL},
	{"physmem_layout", rte_dump_physmem_layout, NULL, NULL},
	{"ring", rte_ring_list_dump, (dump_fn_t)rte_ring_dump, (lookup_fn_t)rte_ring_lookup},
	{"tailq", rte_dump_tailq, NULL, NULL},
	{"trace", rte_trace_dump, NULL, NULL},
	{NULL, NULL, NULL, NULL},
};

static struct api_out obj_dump(const void *request, struct api_ctx *ctx) {
	const struct gr_diagnos_obj_dump_req *req = request;
	const struct obj_dump_helper *helper;
	void *obj = NULL;
	char *buf = NULL;
	size_t len = 0, pos, payload_len;
	FILE *f;

	if (*req->type == 0)
		return api_out(EINVAL, 0, NULL);
	if (strnlen(req->type, sizeof(req->type)) == sizeof(req->type))
		return api_out(ENAMETOOLONG, 0, NULL);

	// Lookup object type.
	for (helper = obj_dump_helpers; helper->type != NULL; helper++)
		if (strncmp(helper->type, req->type, sizeof(req->type)) == 0)
			break;
	if (helper->type == NULL)
		return api_out(EINVAL, 0, NULL); // Object type not supported.

	// If name provided, lookup object.
	if (*req->name != 0) {
		if (strnlen(req->name, sizeof(req->name)) == sizeof(req->name))
			return api_out(ENAMETOOLONG, 0, NULL);
		if (helper->lookup_fn == NULL || helper->dump_fn == NULL)
			return api_out(EINVAL, 0, NULL); // Name lookup/dump not supported.
		if ((obj = helper->lookup_fn(req->name)) == NULL)
			return api_out(ENOENT, 0, NULL); // Not found.
	}

	f = open_memstream(&buf, &len);
	if (obj != NULL)
		helper->dump_fn(f, obj);
	else
		helper->dump_list_fn(f);
	fclose(f);

	for (pos = 0; pos < len; pos += payload_len) {
		payload_len = RTE_MIN((size_t)GR_API_MAX_MSG_LEN, len - pos);
		api_send(ctx, payload_len, buf + pos);
	}

	free(buf);

	return api_out(0, 0, NULL);
}

RTE_INIT(diagnos_init) {
	api_handler(GR_DIAGNOS_OBJ_DUMP, obj_dump);
}
