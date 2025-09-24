// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_nexthop.h>

#include <stdio.h>
#include <sys/queue.h>

struct cli_nexthop_formatter {
	const char *name;
	gr_nh_type_t type;
	ssize_t (*format)(char *buf, size_t len, const void *nexthop_info);
	STAILQ_ENTRY(cli_nexthop_formatter) next;
};

void cli_nexthop_formatter_register(struct cli_nexthop_formatter *);

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
