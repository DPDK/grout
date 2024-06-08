// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#include "control.h"

#include <br_api.h>
#include <br_control.h>
#include <br_log.h>
#include <br_stb_ds.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

static STAILQ_HEAD(, br_api_handler) handlers = STAILQ_HEAD_INITIALIZER(handlers);

void br_register_api_handler(struct br_api_handler *handler) {
	const struct br_api_handler *h;

	assert(handler != NULL);
	assert(handler->callback != NULL);
	assert(handler->name != NULL);
	STAILQ_FOREACH (h, &handlers, entries) {
		if (h->request_type == handler->request_type)
			ABORT("duplicate api handler type=0x%08x '%s'",
			      handler->request_type,
			      handler->name);
	}
	STAILQ_INSERT_TAIL(&handlers, handler, entries);
}

const struct br_api_handler *lookup_api_handler(const struct br_api_request *req) {
	const struct br_api_handler *handler;

	STAILQ_FOREACH (handler, &handlers, entries) {
		if (handler->request_type == req->type)
			return handler;
	}

	return NULL;
}

static STAILQ_HEAD(, br_module) modules = STAILQ_HEAD_INITIALIZER(modules);

void br_register_module(struct br_module *mod) {
	STAILQ_INSERT_TAIL(&modules, mod, entries);
}

static int module_init_prio_order(const void *a, const void *b) {
	const struct br_module *const *mod_a = a;
	const struct br_module *const *mod_b = b;
	return (*mod_a)->init_prio - (*mod_b)->init_prio;
}

void modules_init(struct event_base *ev_base) {
	struct br_module *mod, **mods = NULL;

	STAILQ_FOREACH (mod, &modules, entries)
		arrpush(mods, mod); // NOLINT

	qsort(mods, arrlen(mods), sizeof(struct br_module *), module_init_prio_order);

	for (int i = 0; i < arrlen(mods); i++) {
		mod = mods[i];
		if (mod->init != NULL) {
			LOG(DEBUG, "%s prio %i", mod->name, mod->init_prio);
			mod->init(ev_base);
		}
	}

	arrfree(mods);
}

static int module_fini_prio_order(const void *a, const void *b) {
	const struct br_module *const *mod_a = a;
	const struct br_module *const *mod_b = b;
	return (*mod_a)->fini_prio - (*mod_b)->fini_prio;
}

void modules_fini(struct event_base *ev_base) {
	struct br_module *mod, **mods = NULL;

	STAILQ_FOREACH (mod, &modules, entries)
		arrpush(mods, mod); // NOLINT

	qsort(mods, arrlen(mods), sizeof(struct br_module *), module_fini_prio_order);

	for (int i = 0; i < arrlen(mods); i++) {
		mod = mods[i];
		if (mod->fini != NULL) {
			LOG(DEBUG, "%s prio %i", mod->name, mod->fini_prio);
			mod->fini(ev_base);
		}
	}

	arrfree(mods);
}

void br_modules_dp_init(void) {
	struct br_module *mod;

	STAILQ_FOREACH (mod, &modules, entries) {
		if (mod->init_dp != NULL) {
			LOG(DEBUG, "%s", mod->name);
			mod->init_dp();
		}
	}
}

void br_modules_dp_fini(void) {
	struct br_module *mod;

	STAILQ_FOREACH (mod, &modules, entries) {
		if (mod->fini_dp != NULL) {
			LOG(DEBUG, "%s", mod->name);
			mod->fini_dp();
		}
	}
}
