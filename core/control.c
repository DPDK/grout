// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2023 Robin Jarry

#include "control.h"

#include <br_api.h>
#include <br_control.h>
#include <br_log.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

static LIST_HEAD(, br_api_handler) handlers;

void br_register_api_handler(struct br_api_handler *handler) {
	const struct br_api_handler *h;

	assert(handler != NULL);
	assert(handler->callback != NULL);
	assert(handler->name != NULL);
	LIST_FOREACH (h, &handlers, entries) {
		if (h->request_type == handler->request_type) {
			LOG(EMERG,
			    "duplicate api handler type=0x%08x '%s'",
			    handler->request_type,
			    handler->name);
			abort();
		}
	}
	LIST_INSERT_HEAD(&handlers, handler, entries);
}

const struct br_api_handler *lookup_api_handler(const struct br_api_request *req) {
	const struct br_api_handler *handler;

	LIST_FOREACH (handler, &handlers, entries) {
		if (handler->request_type == req->type)
			return handler;
	}

	return NULL;
}

static LIST_HEAD(, br_module) modules;

void br_register_module(struct br_module *mod) {
	LIST_INSERT_HEAD(&modules, mod, entries);
}

static int module_init_prio_order(const void *a, const void *b) {
	const struct br_module *mod_a = a;
	const struct br_module *mod_b = b;
	return mod_a->init_prio - mod_b->init_prio;
}

void modules_init(void) {
	struct br_module *mod, **sorted;
	int num = 0;

	LIST_FOREACH (mod, &modules, entries)
		num++;

	sorted = calloc(num, sizeof(struct br_module *));
	if (!sorted) {
		LOG(ERR, "Not enough memory");
		return;
	}

	num = 0;
	LIST_FOREACH (mod, &modules, entries)
		sorted[num++] = mod;

	qsort(sorted, num, sizeof(struct br_module *), module_init_prio_order);

	for (int i = 0; i < num; i++) {
		mod = sorted[i];
		if (mod->init != NULL)
			mod->init();
	}

	free(sorted);
}

static int module_fini_prio_order(const void *a, const void *b) {
	const struct br_module *mod_a = a;
	const struct br_module *mod_b = b;
	return mod_a->fini_prio - mod_b->fini_prio;
}

void modules_fini(void) {
	struct br_module *mod, **sorted;
	int num = 0;

	LIST_FOREACH (mod, &modules, entries)
		num++;

	sorted = calloc(num, sizeof(struct br_module *));
	if (!sorted) {
		LOG(ERR, "Not enough memory");
		return;
	}

	num = 0;
	LIST_FOREACH (mod, &modules, entries)
		sorted[num++] = mod;

	qsort(sorted, num, sizeof(struct br_module *), module_fini_prio_order);

	for (int i = 0; i < num; i++) {
		mod = sorted[i];
		if (mod->fini != NULL)
			mod->fini();
	}

	free(sorted);
}
