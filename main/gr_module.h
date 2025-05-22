// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _GR_MODULE
#define _GR_MODULE

#include <event2/event.h>

#include <stdint.h>
#include <sys/queue.h>

struct api_out {
	uint32_t status;
	uint32_t len;
};

static inline struct api_out api_out(uint32_t status, uint32_t len) {
	struct api_out out = {status, len};
	return out;
}

typedef struct api_out (*gr_api_handler_func)(const void *request, void **response);

struct gr_api_handler {
	const char *name;
	uint32_t request_type;
	gr_api_handler_func callback;
	STAILQ_ENTRY(gr_api_handler) entries;
};

void gr_register_api_handler(struct gr_api_handler *);

struct gr_module {
	const char *name;
	const char *depends_on;
	void (*init)(struct event_base *);
	void (*fini)(struct event_base *);
	void (*init_dp)(void);
	void (*fini_dp)(void);
	STAILQ_ENTRY(gr_module) entries;
};

void gr_register_module(struct gr_module *);

void gr_modules_dp_init(void);

void gr_modules_dp_fini(void);

#endif
