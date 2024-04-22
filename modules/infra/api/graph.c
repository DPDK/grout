// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "br_infra.h"

#include <br_api.h>
#include <br_control.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <rte_graph_worker.h>

#include <errno.h>
#include <stdio.h>
#include <sys/queue.h>

static struct api_out graph_dump(const void *request, void **response) {
	struct br_infra_graph_dump_resp *resp;
	size_t buf_len = 0, resp_len = 0;
	const char *graph_name;
	struct worker *worker;
	FILE *stream = NULL;
	char *buf = NULL;
	int ret = 0;

	(void)request;

	LIST_FOREACH (worker, &workers, next) {
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

struct stat_value {
	uint64_t objects;
	uint64_t calls;
	uint64_t cycles;
};

struct stat_entry {
	char *key;
	struct stat_value value;
};

static struct api_out graph_stats(const void *request, void **response) {
	struct br_infra_graph_stats_resp *resp;
	struct stat_entry *smap = NULL;
	struct worker *worker;
	size_t len;
	int ret;

	(void)request;

	sh_new_arena(smap);

	LIST_FOREACH (worker, &workers, next) {
		const struct worker_stats *w_stats = atomic_load(&worker->stats);
		if (w_stats == NULL)
			continue;
		for (unsigned i = 0; i < w_stats->n_stats; i++) {
			const struct node_stats *s = &w_stats->stats[i];
			const char *name = rte_node_id_to_name(s->node_id);
			struct stat_entry *e = shgetp_null(smap, name);
			if (e != NULL) {
				e->value.objects += s->objs;
				e->value.calls += s->calls;
				e->value.cycles += s->cycles;
			} else {
				struct stat_value value = {
					.objects = s->objs,
					.calls = s->calls,
					.cycles = s->cycles,
				};
				shput(smap, name, value);
			}
		}
	}

	len = sizeof(*resp) + shlenu(smap) * sizeof(*resp->stats);
	if ((resp = calloc(1, len)) == NULL) {
		ret = ENOMEM;
		len = 0;
		goto end;
	}

	for (unsigned i = 0; i < shlenu(smap); i++) {
		struct br_infra_graph_stat *s = &resp->stats[i];
		struct stat_entry *e = &smap[i];
		memccpy(s->node, e->key, 0, sizeof(s->node));
		s->objects = e->value.objects;
		s->calls = e->value.calls;
		s->cycles = e->value.cycles;
	}
	resp->n_stats = shlenu(smap);
	*response = resp;
	ret = 0;
end:
	shfree(smap);
	return api_out(ret, len);
}

static struct br_api_handler graph_dump_handler = {
	.name = "graph dump",
	.request_type = BR_INFRA_GRAPH_DUMP,
	.callback = graph_dump,
};
static struct br_api_handler graph_stats_handler = {
	.name = "graph stats",
	.request_type = BR_INFRA_GRAPH_STATS,
	.callback = graph_stats,
};

RTE_INIT(graph_init) {
	br_register_api_handler(&graph_dump_handler);
	br_register_api_handler(&graph_stats_handler);
}
