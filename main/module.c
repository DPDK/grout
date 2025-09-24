// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "module.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_sort.h>
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

	STAILQ_FOREACH (h, &handlers, next) {
		if (h->request_type == handler->request_type)
			ABORT("duplicate api handler type=0x%08x '%s'",
			      handler->request_type,
			      handler->name);
	}
	STAILQ_INSERT_TAIL(&handlers, handler, next);
}

const struct gr_api_handler *lookup_api_handler(const struct gr_api_request *req) {
	const struct gr_api_handler *handler;

	STAILQ_FOREACH (handler, &handlers, next) {
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

	STAILQ_FOREACH (m, &modules, next) {
		if (strcmp(mod->name, m->name) == 0)
			ABORT("duplicate module name: '%s'", mod->name);
	}

	STAILQ_INSERT_TAIL(&modules, mod, next);
}

static bool module_is_child(const void *mod, const void *maybe_child) {
	const struct gr_module *c = maybe_child;
	const struct gr_module *m = mod;

	if (c->depends_on == NULL)
		return false;

	return fnmatch(c->depends_on, m->name, 0) == 0;
}

void modules_init(struct event_base *ev_base) {
	gr_vec const struct gr_module **mods = NULL;
	const struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, next)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	if (topo_sort((gr_vec const void **)mods, module_is_child) < 0)
		ABORT("topo_sort failed: %s", strerror(errno));

	gr_vec_foreach (mod, mods) {
		if (mod->init != NULL) {
			LOG(DEBUG, "'%s' (depends on '%s')", mod->name, mod->depends_on ?: "");
			mod->init(ev_base);
		}
	}

	gr_vec_free(mods);
}

void modules_fini(struct event_base *ev_base) {
	gr_vec const struct gr_module **mods = NULL;
	const struct gr_module *mod;

	STAILQ_FOREACH (mod, &modules, next)
		gr_vec_add(mods, mod);

	if (mods == NULL)
		ABORT("failed to alloc module array");

	if (topo_sort((gr_vec const void **)mods, module_is_child) < 0)
		ABORT("topo_sort failed: %s", strerror(errno));

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
