// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#pragma once

#include <gr_vec.h>

#include <stdbool.h>

typedef bool (*topo_is_parent_cb_t)(const void *node, const void *maybe_parent);
typedef bool (*topo_is_child_cb_t)(const void *node, const void *maybe_child);

// Topologically sort `nodes` in-place.
//
// Exactly one of `is_parent` or `is_child` must be non-NULL.
// Cycles are ignored. Nodes in cycles are visited once and ordered arbitrarily.
int topo_sort(
	gr_vec const void **nodes,
	topo_is_parent_cb_t is_parent,
	topo_is_child_cb_t is_child
);
