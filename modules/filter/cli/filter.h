// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_cli.h>

#define FILTER_ADD_CTX(root)                                                                       \
	CLI_CONTEXT(root, CTX_ADD, CTX_ARG("filter", "Create filter elements."))
#define FILTER_DEL_CTX(root)                                                                       \
	CLI_CONTEXT(root, CTX_DEL, CTX_ARG("filter", "Delete filter elements."))
#define FILTER_SHOW_CTX(root) CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("filter", "Show filter details."))
