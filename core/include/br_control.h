// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_CONTROL
#define _BR_CONTROL

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

typedef struct api_out (*br_api_handler_func)(const void *request, void **response);

struct br_api_handler {
	const char *name;
	uint32_t request_type;
	br_api_handler_func callback;
	LIST_ENTRY(br_api_handler) entries;
};

void br_register_api_handler(struct br_api_handler *);

struct br_module {
	const char *name;
	int init_prio;
	void (*init)(void);
	int fini_prio;
	void (*fini)(void);
	void (*init_dp)(void);
	void (*fini_dp)(void);
	LIST_ENTRY(br_module) entries;
};

void br_register_module(struct br_module *);

void br_modules_dp_init(void);

void br_modules_dp_fini(void);

#endif
