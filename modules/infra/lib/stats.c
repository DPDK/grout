// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_client.h>
#include <br_client_priv.h>
#include <br_infra_msg.h>

#include <errno.h>
#include <stdlib.h>

int br_infra_stats_get(
	const struct br_client *c,
	br_infra_stats_flags_t flags,
	const char *pattern,
	size_t *n_stats,
	struct br_infra_stat **stats
) {
	struct br_infra_stats_get_req req = {.flags = flags};
	const struct br_infra_stats_get_resp *resp;
	void *resp_ptr = NULL;
	int ret = -1;

	if (n_stats == NULL || stats == NULL) {
		errno = EINVAL;
		goto out;
	}
	if (pattern != NULL)
		snprintf(req.pattern, sizeof(req.pattern), "%s", pattern);

	if (send_recv(c, BR_INFRA_STATS_GET, sizeof(req), &req, &resp_ptr) < 0)
		goto out;

	resp = resp_ptr;
	*stats = calloc(resp->n_stats, sizeof(*resp->stats));
	if (*stats == NULL) {
		errno = ENOMEM;
		goto out;
	}

	*n_stats = resp->n_stats;
	memcpy(*stats, resp->stats, resp->n_stats * sizeof(*resp->stats));
	ret = 0;
out:
	free(resp_ptr);
	return ret;
}

int br_infra_stats_reset(const struct br_client *c) {
	return send_recv(c, BR_INFRA_STATS_RESET, 0, NULL, NULL);
}
