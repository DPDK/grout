// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_cli.h>

#define IP6_ADD_CTX(root) CLI_CONTEXT(root, CTX_ADD, CTX_ARG("ip6", "Create IPv6 stack elements."))
#define IP6_DEL_CTX(root) CLI_CONTEXT(root, CTX_DEL, CTX_ARG("ip6", "Delete IPv6 stack elements."))
#define IP6_SHOW_CTX(root) CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("ip6", "Show IPv6 stack details."))
#define IP6_SET_CTX(root) CLI_CONTEXT(root, CTX_SET, CTX_ARG("ip6", "Set IPv6 stack elements."))
#define IP6_CLEAR_CTX(root)                                                                        \
	CLI_CONTEXT(root, CTX_CLEAR, CTX_ARG("ip6", "Clear IPv6 stack elements."))
