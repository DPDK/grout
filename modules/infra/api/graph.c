// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_module.h>
#include <gr_worker.h>

#include <rte_graph_worker.h>

#include <errno.h>
#include <stdio.h>
#include <sys/queue.h>

static struct api_out graph_dump(const void *request, void **response) {
	const struct gr_infra_graph_dump_req *req = request;
	char *buf = NULL, *copy, *line, *prev_line, *eol;
	struct gr_infra_graph_dump_resp *resp;
	size_t buf_len = 0, resp_len = 0;
	const char *graph_name;
	struct worker *worker;
	FILE *stream = NULL;
	int ret = 0;

	if (req->flags & ~GR_INFRA_GRAPH_DUMP_F_ERRORS)
		return api_out(EINVAL, 0);

	STAILQ_FOREACH (worker, &workers, next) {
		for (int i = 0; i < 2; i++) {
			if (worker->graph[i] != NULL) {
				graph_name = worker->graph[i]->name;
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
	resp_len = sizeof(*resp) + buf_len;
	if ((resp = calloc(1, resp_len)) == NULL) {
		ret = -ENOMEM;
		resp_len = 0;
		goto end;
	}

	copy = resp->dot;
	prev_line = NULL;
	line = buf;

	while ((eol = strchr(line, '\n')) != NULL) {
		*eol = '\0';
		// Remove sink nodes from the output. They all have a "darkorange" color.
		// Also remove non-sink nodes that contain "error" in their name.
		bool is_err = strstr(line, "darkorange") || strstr(line, "error");
		// Remove duplicate lines.
		bool is_dup = prev_line != NULL && strncmp(line, prev_line, strlen(line)) == 0;
		if (!is_dup && (req->flags & GR_INFRA_GRAPH_DUMP_F_ERRORS || !is_err)) {
			*eol = '\n'; // restore newline char
			copy = memccpy(copy, line, '\n', eol - line + 1);
		}
		prev_line = line;
		line = eol + 1;
	}

	resp->len = copy - resp->dot;
	resp_len = sizeof(*resp) + resp->len;
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
