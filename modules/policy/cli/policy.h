// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_cli.h>

#define POLICY_ADD_CTX(root)                                                                       \
	CLI_CONTEXT(root, CTX_ADD, CTX_ARG("policy", "Create policy elements."))
#define POLICY_DEL_CTX(root)                                                                       \
	CLI_CONTEXT(root, CTX_DEL, CTX_ARG("policy", "Delete policy elements."))
#define POLICY_SHOW_CTX(root) CLI_CONTEXT(root, CTX_SHOW, CTX_ARG("policy", "Show policy details."))
