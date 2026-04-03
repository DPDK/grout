// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <inttypes.h>
#include <sys/queue.h>

struct cli_event_printer {
	STAILQ_ENTRY(cli_event_printer) next;
	void (*print)(uint32_t ev_type, const void *event);
	unsigned ev_count;
	uint32_t ev_types[];
};

void cli_event_printer_register(struct cli_event_printer *);
