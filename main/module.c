// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "module.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vec.h>

#include <assert.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

static STAILQ_HEAD(, gr_api_handler) handlers = STAILQ_HEAD_INITIALIZER(handlers);

void gr_register_api_handler(struct gr_api_handler *handler) {
	const struct gr_api_handler *h;

	assert(handler != NULL);
	assert(handler->callback != NULL);
	assert(handler->name != NULL);
	switch (handler->request_type) {
	case GR_MAIN_HELLO:
	case GR_MAIN_EVENT_SUBSCRIBE:
	case GR_MAIN_EVENT_UNSUBSCRIBE:
		goto duplicate;
	}

	STAILQ_FOREACH (h, &handlers, entries) {
		if (h->request_type == handler->request_type)
duplicate:
			ABORT("duplicate api handler type=0x%08x '%s'",
			      handler->request_type,
			      handler->name);
	}
	STAILQ_INSERT_TAIL(&handlers, handler, entries);
}

const struct gr_api_handler *lookup_api_handler(const struct gr_api_request *req) {
	const struct gr_api_handler *handler;

	STAILQ_FOREACH (handler, &handlers, entries) {
		if (handler->request_type == req->type)
			return handler;
	}

	return NULL;
}

static STAILQ_HEAD(, gr_module) modules = STAILQ_HEAD_INITIALIZER(modules);

void gr_register_module(struct gr_module *mod) {
	struct gr_module *m;

	if (mod->name == NULL)
		ABORT("module with no name: %p", mod);

	STAILQ_FOREACH (m, &modules, entries) {
		if (strcmp(mod->name, m->name) == 0)
			ABORT("duplicate module name: '%s'", mod->name);
	}

	STAILQ_INSERT_TAIL(&modules, mod, entries);
}

static void topo_sort(struct gr_module **mods) {
	// Create an adjacency matrix representing all edges
	const size_t len = gr_vec_len(mods);
	bool *adj_matrix = calloc(len * len, sizeof(bool));
	if (adj_matrix == NULL)
		ABORT("cannot allocate memory");

	for (unsigned i = 0; i < len; i++) {
		if (mods[i]->depends_on == NULL)
			continue;

		for (unsigned j = 0; j < len; j++) {
			if (fnmatch(mods[i]->depends_on, mods[j]->name, 0) == 0) {
				adj_matrix[j * len + i] = true;
				break;
			}
		}
	}

	// Calculate in-degree of each vertex
	int *in_degree = calloc(len, sizeof(int));
	if (in_degree == NULL)
		ABORT("cannot allocate memory");

	for (unsigned i = 0; i < len; i++) {
		for (unsigned j = 0; j < len; j++) {
			if (adj_matrix[i * len + j]) {
				in_degree[j]++;
			}
		}
	}

	// Kahn's algorithm for topological sort
	unsigned front = 0, rear = 0;
	unsigned *queue = calloc(len, sizeof(unsigned));
	if (queue == NULL)
		ABORT("cannot allocate memory");

	for (unsigned i = 0; i < len; i++) {
		if (in_degree[i] == 0) {
			queue[rear++] = i;
		}
	}

	struct gr_module **sorted = calloc(len, sizeof(struct gr_module *));
	if (sorted == NULL)
		ABORT("cannot allocate memory");

	unsigned i = 0;
	while (front < rear) {
		unsigned u = queue[front++];
		sorted[i++] = mods[u];

		// Reduce in-degree of neighbours
		for (unsigned v = 0; v < len; v++) {
			if (adj_matrix[u * len + v]) {
				in_degree[v]--;
				if (in_degree[v] == 0) {
					queue[rear++] = v;
				}
			}
		}
	}

	// Copy the sorted modules back to the original array
	memcpy(mods, sorted, len * sizeof(struct gr_module *));

	free(sorted);
	free(queue);
	free(in_degree);
	free(adj_matrix);
}

void modules_init(struct event_base *ev_base) {
	gr_vec struct gr_module **mods = NULL;
	struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, entries)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	topo_sort(mods);

	gr_vec_foreach (mod, mods) {
		if (mod->init != NULL) {
			LOG(DEBUG, "'%s' (depends on '%s')", mod->name, mod->depends_on ?: "");
			mod->init(ev_base);
		}
	}

	gr_vec_free(mods);
}

void modules_fini(struct event_base *ev_base) {
	gr_vec struct gr_module **mods = NULL;
	struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, entries)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	topo_sort(mods);

	// call fini() functions in reverse topological order
	for (int i = gr_vec_len(mods) - 1; i >= 0; i--) {
		mod = mods[i];
		if (mod->fini != NULL) {
			LOG(DEBUG, "'%s' (depends on '%s')", mod->name, mod->depends_on ?: "");
			mod->fini(ev_base);
		}
	}

	gr_vec_free(mods);
}
