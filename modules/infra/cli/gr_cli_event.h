// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <inttypes.h>
#include <sys/queue.h>

struct gr_cli_event_printer {
	STAILQ_ENTRY(gr_cli_event_printer) next;
	void (*print)(uint32_t ev_type, const void *event);
	unsigned ev_count;
	uint32_t ev_types[];
};

void gr_cli_event_register_printer(struct gr_cli_event_printer *);
