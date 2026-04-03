// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include "display.h"

#include <gr_nexthop.h>

#include <stdio.h>
#include <sys/queue.h>

struct cli_nexthop_formatter {
	const char *name;
	gr_nh_type_t type;
	// Optional: single-line text for INFO column. Only needed for types
	// with arrays/sub-objects in fill_object (group, srv6). When NULL,
	// cli_nexthop_format uses fill_object with compact separators.
	ssize_t (*format)(char *buf, size_t len, const void *nexthop_info);
	// Define type-specific columns in a table (called once).
	void (*add_columns)(struct gr_table *);
	// Fill type-specific cells in a table row.
	void (*fill_table)(struct gr_table *, unsigned start_col, const void *nexthop_info);
	// Fill type-specific fields in a gr_object.
	void (*fill_object)(struct gr_object *, const void *nexthop_info);
	STAILQ_ENTRY(cli_nexthop_formatter) next;
};

void cli_nexthop_formatter_register(struct cli_nexthop_formatter *);

// Fill nexthop fields into a gr_object.
// If with_base_info is true, include base fields (type, id, iface, vrf, origin).
void cli_nexthop_fill_object(
	struct gr_object *,
	struct gr_api_client *,
	const struct gr_nexthop *,
	bool with_base_info
);

// Format nexthop as a single-line string (for mixed-type tables).
// Uses fill_object with "=" and " " separators internally.
ssize_t cli_nexthop_format(
	char *buf,
	size_t len,
	struct gr_api_client *,
	const struct gr_nexthop *,
	bool with_base_info
);

#define NEXTHOP_ARG CTX_ARG("nexthop", "Nexthops.")
#define NEXTHOP_CTX(root) CLI_CONTEXT(root, NEXTHOP_ARG)
#define NEXTHOP_ADD_CTX(root)                                                                      \
	CLI_CONTEXT(root, NEXTHOP_ARG, CTX_ARG("add", "Create a new nexthop."))
