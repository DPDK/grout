// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "config.h"
#include "log.h"
#include "module.h"

#include <gr_api.h>
#include <gr_string.h>

#include <rte_common.h>
#include <rte_log.h>

#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

static struct api_out log_packets_set(const void *request, struct api_ctx *) {
	const struct gr_log_packets_set_req *req = request;
	gr_config.log_packets = req->enabled;
	return api_out(0, 0, NULL);
}

static struct api_out log_level_list(const void *request, struct api_ctx *ctx) {
	const struct gr_log_level_list_req *req = request;
	struct gr_log_entry entry;
	struct gr_log_type *t;

	STAILQ_FOREACH (t, &gr_log_types, next) {
		memset(&entry, 0, sizeof(entry));
		snprintf(entry.name, sizeof(entry.name), "%s", t->name);
		entry.level = rte_log_get_level(t->type_id);
		api_send(ctx, sizeof(entry), &entry);
	}

	if (req->show_all) {
		char name[64], level_str[32];
		char *buf = NULL;
		size_t len = 0;
		FILE *f;

		f = open_memstream(&buf, &len);
		if (f == NULL)
			return api_out(errno, 0, NULL);
		rte_log_dump(f);
		fclose(f);

		for (char *line = strtok(buf, "\n"); line != NULL; line = strtok(NULL, "\n")) {
			if (sscanf(line, "id %*u: %63[^,], level is %31s", name, level_str) != 2)
				continue;
			if (strncmp(name, "grout.", 6) == 0)
				continue;
			memset(&entry, 0, sizeof(entry));
			snprintf(entry.name, sizeof(entry.name), "%s", name);
			entry.level = gr_log_level_parse(level_str);
			api_send(ctx, sizeof(entry), &entry);
		}

		free(buf);
	}

	return api_out(0, 0, NULL);
}

static struct api_out log_level_set(const void *request, struct api_ctx *) {
	const struct gr_log_level_set_req *req = request;

	if (strnlen(req->pattern, sizeof(req->pattern)) == sizeof(req->pattern))
		return api_out(ENAMETOOLONG, 0, NULL);
	if (req->level > RTE_LOG_MAX)
		return api_out(EINVAL, 0, NULL);

	rte_log_set_level_pattern(req->pattern, req->level);

	return api_out(0, 0, NULL);
}

RTE_INIT(log_api_init) {
	gr_api_handler(GR_LOG_PACKETS_SET, log_packets_set);
	gr_api_handler(GR_LOG_LEVEL_LIST, log_level_list);
	gr_api_handler(GR_LOG_LEVEL_SET, log_level_set);
}
