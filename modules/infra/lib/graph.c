// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int br_infra_graph_dump(const struct br_client *c, size_t *len, char **dot) {
	struct br_infra_graph_dump_resp *resp = NULL;
	int ret = -1;

	if (len == NULL || dot == NULL) {
		errno = EINVAL;
		goto out;
	}
	if (send_recv(c, BR_INFRA_GRAPH_DUMP, 0, NULL, (void *)&resp) < 0)
		goto out;

	*dot = calloc(1, resp->len);
	if (*dot == NULL) {
		errno = ENOMEM;
		goto out;
	}
	*len = resp->len;
	memcpy(*dot, resp->dot, resp->len);
	ret = 0;
out:
	free(resp);
	return ret;
}

int br_infra_graph_stats(
	const struct br_client *c,
	size_t *n_stats,
	struct br_infra_graph_stat **stats
) {
	struct br_infra_graph_stats_resp *resp = NULL;
	int ret = -1;

	if (n_stats == NULL || stats == NULL) {
		errno = EINVAL;
		goto out;
	}

	if (send_recv(c, BR_INFRA_GRAPH_STATS, 0, NULL, (void *)&resp) < 0)
		goto out;

	*stats = calloc(resp->n_stats, sizeof(*resp->stats));
	if (*stats == NULL) {
		errno = ENOMEM;
		goto out;
	}

	*n_stats = resp->n_stats;
	memcpy(*stats, resp->stats, resp->n_stats * sizeof(*resp->stats));
	ret = 0;
out:
	free(resp);
	return ret;
}
