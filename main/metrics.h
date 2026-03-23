// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

enum metric_type {
	METRIC_COUNTER,
	METRIC_GAUGE,
	METRIC_HISTOGRAM,
	METRIC_GAUGE_HISTOGRAM,
};

// Metric definition (static, registered once per metric name)
struct metric {
	const char *name; // will be prefixed with "grout_"
	const char *help;
	enum metric_type type;
};

// Convenience macros for static metric definitions.
#define METRIC_COUNTER(v, n, h)                                                                    \
	static const struct metric v = {.name = (n), .help = (h), .type = METRIC_COUNTER}
#define METRIC_GAUGE(v, n, h)                                                                      \
	static const struct metric v = {.name = (n), .help = (h), .type = METRIC_GAUGE}
#define METRIC_HISTOGRAM(v, n, h)                                                                  \
	static const struct metric v = {.name = (n), .help = (h), .type = METRIC_HISTOGRAM}
#define METRIC_GAUGE_HISTOGRAM(v, n, h)                                                            \
	static const struct metric v = {.name = (n), .help = (h), .type = METRIC_GAUGE_HISTOGRAM}

// Opaque writer context
struct metrics_writer;

// Label context - holds base labels for multiple emit calls
struct metrics_ctx {
	struct metrics_writer *w;
	char labels[512];
	size_t labels_len;
};

// Initialize context with base labels (varargs: key, val, ..., NULL)
void metrics_ctx_init(struct metrics_ctx *, struct metrics_writer *, ...);

// Add more labels to existing context (varargs: key, val, ..., NULL)
void metrics_labels_add(struct metrics_ctx *, ...);

// Emit metric value using context's labels
void metric_emit(struct metrics_ctx *, const struct metric *, uint64_t value);

// Emit a histogram metric. slot_counts[i] is the count of observations with
// value exactly i. bucket_bounds[] defines which slot indices are emitted as
// le="N" bucket boundaries.
void metric_emit_histogram(
	struct metrics_ctx *,
	const struct metric *,
	const uint64_t *slot_counts,
	unsigned n_slots,
	const unsigned *bucket_bounds,
	unsigned n_buckets
);

// Collector registration (groups related metrics + callback)
struct metrics_collector {
	const char *name;
	void (*collect)(struct metrics_writer *);
	STAILQ_ENTRY(metrics_collector) next;
};

void metrics_register(struct metrics_collector *);

// Start the openmetrics HTTP server in a dedicated thread
void metrics_start(void);

// Stop the openmetrics HTTP server
void metrics_stop(void);

// Change the thread affinity of the openmetrics thread
int metrics_set_affinity(size_t set_size, const cpu_set_t *affinity);
