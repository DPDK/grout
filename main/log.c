// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "clock.h"
#include "config.h"
#include "log.h"
#include "module.h"

#include <gr_api.h>
#include <gr_string.h>

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

struct log_counters log_counters = STAILQ_HEAD_INITIALIZER(log_counters);

void log_counter_register(struct log_counter *c) {
	STAILQ_INSERT_TAIL(&log_counters, c, next);
}

bool log_counter_rate_limited(struct log_counter *c, uint64_t *suppressed) {
	gr_clock_ns_t now = clock_ns();

	// Rate limiting is only meant for control-plane (main thread) code. The
	// datapath accounts for errors through drop nodes instead.
	assert(rte_lcore_has_role(rte_lcore_id(), ROLE_RTE));
	assert(c != NULL);
	assert(suppressed != NULL);

	*suppressed = 0;
	if (gr_config.log_max_rate == 0)
		return false;

	uint64_t add = (now - c->last_refill) * gr_config.log_max_rate / GR_NS_PER_S;
	if (add > 0) {
		c->tokens = RTE_MIN(c->tokens - add, gr_config.log_max_rate);
		c->last_refill = now;
	}

	if (c->tokens == 0) {
		c->suppressed++;
		return true;
	}

	c->tokens--;
	*suppressed = c->suppressed;
	c->suppressed = 0;

	return false;
}

void log_counter_reset_all(void) {
	struct log_counter *c;

	STAILQ_FOREACH (c, &log_counters, next) {
		c->count = 0;
		c->suppressed = 0;
		c->last_refill = 0;
		c->tokens = 0;
	}
}

static struct api_out log_packets_set(const void *request, struct api_ctx *) {
	const struct gr_log_packets_set_req *req = request;
	gr_config.log_packets = req->enabled;
	return api_out(0, 0, NULL);
}

static struct api_out log_level_list(const void *request, struct api_ctx *ctx) {
	const struct gr_log_level_list_req *req = request;
	struct gr_log_entry entry;
	struct log_type *t;

	STAILQ_FOREACH (t, &log_types, next) {
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

static struct api_out log_rate_set(const void *request, struct api_ctx *) {
	const struct gr_log_rate_set_req *req = request;

	gr_config.log_max_rate = req->rate;

	return api_out(0, 0, NULL);
}

static struct api_out log_rate_get(const void * /*request*/, struct api_ctx *) {
	struct gr_log_rate_get_resp *resp = malloc(sizeof(*resp));

	if (resp == NULL)
		return api_out(ENOMEM, 0, NULL);

	resp->rate = gr_config.log_max_rate;

	return api_out(0, sizeof(*resp), resp);
}

RTE_INIT(log_api_init) {
	api_handler(GR_LOG_PACKETS_SET, log_packets_set);
	api_handler(GR_LOG_LEVEL_LIST, log_level_list);
	api_handler(GR_LOG_LEVEL_SET, log_level_set);
	api_handler(GR_LOG_RATE_SET, log_rate_set);
	api_handler(GR_LOG_RATE_GET, log_rate_get);
}
