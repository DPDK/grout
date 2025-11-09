// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#pragma once

#include <ecoli.h>

int bash_complete(struct ec_node *cmdlist);
struct ec_node *grcli_options_node(void);
