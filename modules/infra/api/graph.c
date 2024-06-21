// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "gr_infra.h"

#include <gr_api.h>
#include <gr_control.h>
#include <gr_worker.h>

#include <rte_graph_worker.h>

#include <errno.h>
#include <stdio.h>
#include <sys/queue.h>

static struct api_out graph_dump(const void *request, void **response) {
	struct gr_infra_graph_dump_resp *resp;
	size_t buf_len = 0, resp_len = 0;
	const char *graph_name;
	struct worker *worker;
	FILE *stream = NULL;
	char *buf = NULL;
	int ret = 0;

	(void)request;

	STAILQ_FOREACH (worker, &workers, next) {
		for (int i = 0; i < 2; i++) {
			if (worker->config[i].graph != NULL) {
				graph_name = worker->config[i].graph->name;
				goto found;
			}
		}
	}
	return api_out(ENODEV, 0);
found:
	if ((stream = open_memstream(&buf, &buf_len)) == NULL)
		return api_out(errno, 0);

	if ((ret = rte_graph_export(graph_name, stream)) < 0)
		goto end;
	fflush(stream);
	resp_len = sizeof(*resp) + buf_len + 1;
	if ((resp = calloc(1, resp_len)) == NULL) {
		ret = -ENOMEM;
		resp_len = 0;
		goto end;
	}

	resp->len = buf_len + 1;
	memccpy(resp->dot, buf, 0, buf_len + 1);
	*response = resp;
end:
	fclose(stream);
	free(buf);
	return api_out(-ret, resp_len);
}

static struct gr_api_handler graph_dump_handler = {
	.name = "graph dump",
	.request_type = GR_INFRA_GRAPH_DUMP,
	.callback = graph_dump,
};

RTE_INIT(graph_init) {
	gr_register_api_handler(&graph_dump_handler);
}
