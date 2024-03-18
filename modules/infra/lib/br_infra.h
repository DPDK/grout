// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA
#define _BR_INFRA

#include <br_client.h>
#include <br_infra_msg.h>
#include <br_infra_types.h>

#include <stddef.h>

int br_infra_port_add(const struct br_client *, const char *devargs, uint16_t *port_id);
int br_infra_port_del(const struct br_client *, uint16_t port_id);
int br_infra_port_get(const struct br_client *, uint16_t port_id, struct br_infra_port *);
int br_infra_port_list(const struct br_client *, size_t *n_ports, struct br_infra_port **);
int br_infra_port_set(
	const struct br_client *,
	uint16_t port_id,
	uint16_t n_rxq,
	uint16_t q_size,
	uint16_t burst
);

int br_infra_rxq_list(const struct br_client *, size_t *n_rxqs, struct br_infra_rxq **);
int br_infra_rxq_set(const struct br_client *, uint16_t port_id, uint16_t rxq_id, uint16_t cpu_id);

int br_infra_stats_get(const struct br_client *, br_infra_stats_flags_t, const char *pattern, size_t *n_stats, struct br_infra_stat **);
int br_infra_stats_reset(const struct br_client *);

int br_infra_graph_dump(const struct br_client *, size_t *len, char **dot);
int br_infra_graph_stats(const struct br_client *, size_t *n_stats, struct br_infra_graph_stat **);

#endif
