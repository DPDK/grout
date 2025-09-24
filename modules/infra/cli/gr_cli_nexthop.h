// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_nexthop.h>

#include <stdio.h>
#include <sys/queue.h>

struct gr_cli_nexthop_formatter {
	const char *name;
	gr_nh_type_t type;
	ssize_t (*format)(char *buf, size_t len, const void *nexthop_info);
	STAILQ_ENTRY(gr_cli_nexthop_formatter) next;
};

void gr_cli_nexthop_register_formatter(struct gr_cli_nexthop_formatter *);

ssize_t gr_cli_format_nexthop(
	char *buf,
	size_t len,
	struct gr_api_client *,
	const struct gr_nexthop *,
	bool with_base_info
);
