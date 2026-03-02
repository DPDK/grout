// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "module.h"

#include <gr_api.h>
#include <gr_log.h>
#include <gr_macro.h>
#include <gr_module.h>
#include <gr_sort.h>
#include <gr_vec.h>

#include <assert.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

struct module_handlers {
	struct api_handler handlers[UINT_NUM_VALUES(uint16_t)];
};

static struct module_handlers *mod_handlers[UINT_NUM_VALUES(uint16_t)];

void __gr_api_handler(uint32_t request_type, gr_api_handler_func callback, const char *name) {
	uint16_t mod = (request_type >> 16) & 0xffff;
	uint16_t req = request_type & 0xffff;
	struct module_handlers *mh;

	assert(callback != NULL);
	assert(name != NULL);

	mh = mod_handlers[mod];
	if (mh == NULL) {
		mod_handlers[mod] = mh = calloc(1, sizeof(*mh));
		if (mh == NULL)
			ABORT("calloc(module_handlers)");
	}
	if (mh->handlers[req].callback != NULL)
		ABORT("duplicate api handler type=0x%08x '%s'", request_type, name);

	mh->handlers[req].callback = callback;
	mh->handlers[req].name = name;
}

const struct api_handler *lookup_api_handler(uint32_t request_type) {
	uint16_t mod = (request_type >> 16) & 0xffff;
	uint16_t req = request_type & 0xffff;
	struct module_handlers *mh = mod_handlers[mod];

	if (mh == NULL || mh->handlers[req].callback == NULL)
		return NULL;

	return &mh->handlers[req];
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
	char depends_on[512];

	if (c->depends_on == NULL)
		return false;

	// split on commas
	assert(strlen(c->depends_on) < sizeof(depends_on));
	memccpy(depends_on, c->depends_on, 0, sizeof(depends_on));

	for (char *dep = strtok(depends_on, ","); dep != NULL; dep = strtok(NULL, ",")) {
		if (fnmatch(dep, m->name, 0) == 0)
			return true;
	}

	return false;
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

	for (unsigned i = 0; i < ARRAY_DIM(mod_handlers); i++) {
		free(mod_handlers[i]);
		mod_handlers[i] = NULL;
	}
}
