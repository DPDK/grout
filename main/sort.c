// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Robin Jarry

#include <gr_errno.h>
#include <gr_sort.h>

#include <stdbool.h>
#include <stdlib.h>

static bool *build_adjacency_matrix(gr_vec const void **nodes, topo_is_child_cb_t is_child) {
	const unsigned len = gr_vec_len(nodes);
	bool *matrix = calloc(len * len, sizeof(*matrix));
	if (matrix == NULL)
		return errno_set_null(ENOMEM);

	for (unsigned i = 0; i < len; i++) {
		for (unsigned j = 0; j < len; j++) {
			if (i == j)
				continue;
			matrix[i * len + j] = is_child(nodes[i], nodes[j]);
		}
	}

	return matrix;
}

typedef enum {
	UNVISITED = 0,
	VISITING,
	VISITED,
} visit_t;

static void dfs_visit(
	unsigned node,
	visit_t *state,
	bool *matrix,
	gr_vec const void **nodes,
	const void **sorted,
	unsigned *order
) {
	const unsigned len = gr_vec_len(nodes);
	state[node] = VISITING;
	for (unsigned n = 0; n < len; n++) {
		if (matrix[node * len + n] && state[n] == UNVISITED)
			dfs_visit(n, state, matrix, nodes, sorted, order);
	}
	state[node] = VISITED;
	// Store the node in the sorted array *after* visiting all its children subtrees.
	// This means the "sink" nodes will be first and "source" nodes will be at the end.
	sorted[(*order)++] = nodes[node];
}

int topo_sort(gr_vec const void **nodes, topo_is_child_cb_t is_child) {
	if (is_child == NULL)
		return errno_set(EINVAL);

	const unsigned len = gr_vec_len(nodes);
	const void **sorted = NULL;
	visit_t *state = NULL;
	bool *matrix = NULL;

	if (len == 0)
		return 0;

	matrix = build_adjacency_matrix(nodes, is_child);
	if (matrix == NULL)
		goto out;

	state = calloc(len, sizeof(*state));
	if (state == NULL)
		goto out;
	for (unsigned i = 0; i < len; i++)
		state[i] = UNVISITED;

	sorted = calloc(len, sizeof(*sorted));
	if (sorted == NULL)
		goto out;

	// Visit all nodes once using recursive depth first search.
	// Store them starting from the deepest chains in the sorted array.
	unsigned order = 0;
	for (unsigned node = 0; node < len; node++) {
		if (state[node] == UNVISITED)
			dfs_visit(node, state, matrix, nodes, sorted, &order);
	}

	// Copy in reverse to get topological order.
	for (unsigned i = 0; i < len; i++)
		nodes[i] = sorted[len - 1 - i];

	errno = 0;
out:
	free(matrix);
	free(state);
	free(sorted);
	return errno_set(errno);
}
