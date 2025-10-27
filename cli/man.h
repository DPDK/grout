// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Abhiram R N

#pragma once

#include <ecoli.h>

int print_man_page(struct ec_node *cmdlist, int argc, char **argv);
int print_main_man_page(struct ec_node *cmdlist);
void man_print_title_underline(const char *title);
