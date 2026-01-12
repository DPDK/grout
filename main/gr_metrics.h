// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

enum gr_metric_type {
	GR_METRIC_COUNTER,
	GR_METRIC_GAUGE,
};

// Metric definition (static, registered once per metric name)
struct gr_metric {
	const char *name; // will be prefixed with "grout_"
	const char *help;
	enum gr_metric_type type;
};

// Convenience macros for static metric definitions.
#define METRIC_COUNTER(v, n, h)                                                                    \
	static const struct gr_metric v = {.name = (n), .help = (h), .type = GR_METRIC_COUNTER}
#define METRIC_GAUGE(v, n, h)                                                                      \
	static const struct gr_metric v = {.name = (n), .help = (h), .type = GR_METRIC_GAUGE}

// Opaque writer context
struct gr_metrics_writer;

// Label context - holds base labels for multiple emit calls
struct gr_metrics_ctx {
	struct gr_metrics_writer *w;
	char labels[512];
	size_t labels_len;
};

// Initialize context with base labels (varargs: key, val, ..., NULL)
void gr_metrics_ctx_init(struct gr_metrics_ctx *, struct gr_metrics_writer *, ...);

// Add more labels to existing context (varargs: key, val, ..., NULL)
void gr_metrics_labels_add(struct gr_metrics_ctx *, ...);

// Emit metric value using context's labels
void gr_metric_emit(struct gr_metrics_ctx *, const struct gr_metric *, uint64_t value);

// Collector registration (groups related metrics + callback)
struct gr_metrics_collector {
	const char *name;
	void (*collect)(struct gr_metrics_writer *);
	STAILQ_ENTRY(gr_metrics_collector) next;
};

void gr_metrics_register(struct gr_metrics_collector *);

// Start the openmetrics HTTP server in a dedicated thread
void gr_metrics_start(void);

// Stop the openmetrics HTTP server
void gr_metrics_stop(void);

// Change the thread affinity of the openmetrics thread
int gr_metrics_set_affinity(size_t set_size, const cpu_set_t *affinity);
