// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 SmartShare Systems

#include "clock.h"
#include "log.h"
#include "module.h"

#include <event2/event.h>

LOG_TYPE("main");

__thread bool clock_trusted = false;

__thread gr_clock_ns_t clock_snapshot_ns = INT64_C(-1);

__thread gr_wallclock_ns_t wallclock_snapshot_ns = INT64_C(-1);

_Atomic gr_clock_ns_t clock_wallclock_offset = INT64_C(-1);

static void wallclock_update_cb(evutil_socket_t, short, void *) {
	atomic_store_explicit(
		&clock_wallclock_offset, gr_wallclock_ns() - gr_clock_ns(), memory_order_relaxed
	);
}

static struct event *wallclock_tick;

static void clock_init(struct event_base *ev_base) {
	atomic_store_explicit(
		&clock_wallclock_offset, gr_wallclock_ns() - gr_clock_ns(), memory_order_relaxed
	);

	wallclock_tick = event_new(
		ev_base, -1, EV_PERSIST | EV_FINALIZE, wallclock_update_cb, NULL
	);
	if (wallclock_tick == NULL)
		ABORT("event_new() failed");
	if (event_add(wallclock_tick, &(struct timeval) {.tv_sec = 1}) == -1)
		ABORT("event_add() failed");
}

static void clock_fini(struct event_base *) {
	event_free(wallclock_tick);
}

static struct module module = {
	.name = "clock",
	.init = clock_init,
	.fini = clock_fini,
};

RTE_INIT(clock_module_init) {
	module_register(&module);
}
