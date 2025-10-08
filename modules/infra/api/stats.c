// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_telemetry.h>

#include <fnmatch.h>

static struct gr_infra_stat *find_stat(gr_vec struct gr_infra_stat *stats, const char *name) {
	struct gr_infra_stat *s;

	gr_vec_foreach_ref (s, stats) {
		if (strncmp(s->name, name, sizeof(s->name)) == 0)
			return s;
	}

	return errno_set_null(ENOENT);
}

static gr_vec struct gr_infra_stat *graph_stats(uint16_t cpu_id) {
	uint64_t loop_cycles = 0, node_cycles = 0, n_loops = 0, pkts = 0;
	gr_vec struct gr_infra_stat *stats = NULL;
	struct gr_infra_stat *s;
	struct worker *worker;

	STAILQ_FOREACH (worker, &workers, next) {
		const struct worker_stats *w_stats = atomic_load(&worker->stats);
		if (w_stats == NULL)
			continue;
		if (cpu_id != UINT16_MAX && worker->cpu_id != cpu_id)
			continue;
		for (unsigned i = 0; i < w_stats->n_stats; i++) {
			const struct node_stats *n = &w_stats->stats[i];
			const char *name = rte_node_id_to_name(n->node_id);
			s = find_stat(stats, name);
			if (s != NULL) {
				s->packets += n->packets;
				s->batches += n->batches;
				s->cycles += n->cycles;
			} else {
				struct gr_infra_stat stat = {
					.packets = n->packets,
					.batches = n->batches,
					.cycles = n->cycles,
					.topo_order = n->topo_order,
				};
				memccpy(stat.name, name, 0, sizeof(stat.name));
				gr_vec_add(stats, stat);
			}
			if (strncmp(name, "port_rx-", strlen("port_rx-")) == 0
			    || strcmp(name, "control_input") == 0)
				pkts += n->packets;
			node_cycles += n->cycles;
		}
		s = find_stat(stats, "idle");
		if (s != NULL) {
			s->batches += w_stats->n_sleeps;
			s->cycles += w_stats->sleep_cycles;
		} else {
			struct gr_infra_stat stat = {
				.packets = 0,
				.batches = w_stats->n_sleeps,
				.cycles = w_stats->sleep_cycles,
				.topo_order = UINT64_MAX,
			};
			memccpy(stat.name, "idle", 0, sizeof(stat.name));
			gr_vec_add(stats, stat);
		}
		loop_cycles += w_stats->loop_cycles - w_stats->sleep_cycles;
		n_loops += w_stats->n_loops;
	}

	struct gr_infra_stat stat = {
		.packets = pkts,
		.batches = n_loops,
		.cycles = loop_cycles - node_cycles,
		.topo_order = UINT64_MAX - 1,
	};
	memccpy(stat.name, "overhead", 0, sizeof(stat.name));
	gr_vec_add(stats, stat);

	return stats;
}

static bool skip_stat(const struct gr_infra_stat *s, gr_infra_stats_flags_t flags) {
	if (flags & GR_INFRA_STAT_F_ZERO)
		return false;

	if (s->packets != 0)
		return false;

	if (strcmp(s->name, "idle") == 0 || strcmp(s->name, "overhead") == 0) {
		if (s->batches != 0)
			return false;
	}

	return true;
}

static struct api_out stats_get(const void *request, struct api_ctx *) {
	const struct gr_infra_stats_get_req *req = request;
	struct gr_infra_stats_get_resp *resp = NULL;
	gr_vec struct gr_infra_stat *stats = NULL;
	struct gr_infra_stat *s;
	size_t len, n_stats;
	int ret;

	if (req->flags & GR_INFRA_STAT_F_SW) {
		stats = graph_stats(req->cpu_id);
		if (stats == NULL && req->cpu_id != UINT16_MAX)
			return api_out(ENODEV, 0, NULL);
	}

	if (req->flags & GR_INFRA_STAT_F_HW) {
		struct rte_eth_xstat_name *names = NULL;
		struct rte_eth_xstat *xstats = NULL;
		struct iface *iface = NULL;
		unsigned num;

		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct iface_info_port *port = iface_info_port(iface);

			// call first with NULL/0 to get the exact count
			if ((ret = rte_eth_xstats_get(port->port_id, NULL, 0)) < 0)
				goto err;
			if (ret == 0)
				continue;
			num = ret;

			if ((xstats = calloc(num, sizeof(*xstats))) == NULL) {
				ret = -ENOMEM;
				goto free_xstat;
			}
			if ((ret = rte_eth_xstats_get(port->port_id, xstats, num)) < 0)
				goto free_xstat;

			if ((names = calloc(num, sizeof(*names))) == NULL) {
				ret = -ENOMEM;
				goto free_xstat;
			}
			if ((ret = rte_eth_xstats_get_names(port->port_id, names, num)) < 0)
				goto free_xstat;

			// xstats and names are matched by array index
			for (unsigned i = 0; i < num; i++) {
				struct gr_infra_stat stat = {
					.packets = xstats[i].value,
					.batches = 0,
					.cycles = 0,
				};
				// prefix each xstat name with interface name
				snprintf(
					stat.name,
					sizeof(stat.name),
					"%s.%s",
					iface->name,
					names[i].name
				);
				gr_vec_add(stats, stat);
			}
free_xstat:
			free(xstats);
			xstats = NULL;
			free(names);
			names = NULL;
			if (ret < 0)
				goto err;
		}
	}

	// iterate once to determine the number of stats matching pattern
	n_stats = 0;
	gr_vec_foreach_ref (s, stats) {
		if (skip_stat(s, req->flags))
			continue;
		switch (fnmatch(req->pattern, s->name, 0)) {
		case 0:
			n_stats++;
		case FNM_NOMATCH:
			continue;
		default:
			ret = -errno;
			goto err;
		}
	}

	// allocate correct response size
	len = sizeof(*resp) + n_stats * sizeof(struct gr_infra_stat);
	if ((resp = calloc(1, len)) == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	// fill in response
	gr_vec_foreach_ref (s, stats) {
		if (skip_stat(s, req->flags))
			continue;
		switch (fnmatch(req->pattern, s->name, 0)) {
		case 0:
			resp->stats[resp->n_stats++] = *s;
		case FNM_NOMATCH:
			continue;
		default:
			ret = -errno;
			goto err;
		}
	}

	gr_vec_free(stats);
	return api_out(0, len, resp);
err:
	gr_vec_free(stats);
	free(resp);
	return api_out(-ret, 0, NULL);
}

static struct api_out stats_reset(const void * /*request*/, struct api_ctx *) {
	struct worker *worker;
	struct iface *iface;
	int ret;

	STAILQ_FOREACH (worker, &workers, next) {
		atomic_store(&worker->stats_reset, true);
		worker_signal_ready(worker);
	}

	iface = NULL;

	// Reset software stats for all interfaces.
	memset(iface_stats, 0, sizeof(iface_stats));

	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *port = iface_info_port(iface);
		if ((ret = rte_eth_stats_reset(port->port_id)) < 0)
			return api_out(-ret, 0, NULL);
		if ((ret = rte_eth_xstats_reset(port->port_id)) < 0)
			return api_out(-ret, 0, NULL);
	}

	return api_out(0, 0, NULL);
}

static struct api_out iface_stats_get(const void * /*request*/, struct api_ctx *) {
	struct gr_infra_iface_stats_get_resp *resp = NULL;
	gr_vec struct gr_iface_stats *stats_vec = NULL;
	struct iface *iface = NULL;
	int ret = 0;

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		// Create a single stats object per interface
		struct gr_iface_stats s;
		s.iface_id = iface->id;
		s.rx_packets = 0;
		s.rx_bytes = 0;
		s.rx_drops = 0;
		s.tx_packets = 0;
		s.tx_bytes = 0;
		s.tx_errors = 0;

		// Aggregate per-core stats
		for (int i = 0; i < RTE_MAX_LCORE; i++) {
			struct iface_stats *sw_stats = iface_get_stats(i, iface->id);
			s.rx_packets += sw_stats->rx_packets;
			s.rx_bytes += sw_stats->rx_bytes;
			s.tx_packets += sw_stats->tx_packets;
			s.tx_bytes += sw_stats->tx_bytes;
		}

		if (iface->type == GR_IFACE_TYPE_PORT) {
			// If possible, use the hardware statistics from the driver
			struct iface_info_port *port = iface_info_port(iface);
			struct rte_eth_stats stats = {0};
			if (rte_eth_stats_get(port->port_id, &stats) == 0) {
				s.rx_drops = stats.imissed;
				s.tx_errors = stats.oerrors;
			}
		}

		gr_vec_add(stats_vec, s);
	}

	size_t n_stats = gr_vec_len(stats_vec);
	size_t len = sizeof(*resp) + n_stats * sizeof(struct gr_iface_stats);
	if ((resp = calloc(1, len)) == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	resp->n_stats = n_stats;
	if (gr_vec_len(stats_vec) > 0)
		memcpy(resp->stats, stats_vec, n_stats * sizeof(struct gr_iface_stats));

	gr_vec_free(stats_vec);
	return api_out(0, len, resp);
err:
	gr_vec_free(stats_vec);
	free(resp);
	return api_out(-ret, 0, NULL);
}

static int
telemetry_sw_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	gr_vec struct gr_infra_stat *stats = graph_stats(UINT16_MAX);
	struct gr_infra_stat *s;

	rte_tel_data_start_dict(d);

	gr_vec_foreach_ref (s, stats) {
		if (s->batches > 0) {
			struct rte_tel_data *val = rte_tel_data_alloc();
			if (val == NULL) {
				goto err;
			}
			rte_tel_data_start_dict(val);
			rte_tel_data_add_dict_uint(val, "packets", s->packets);
			rte_tel_data_add_dict_uint(val, "batches", s->batches);
			rte_tel_data_add_dict_uint(val, "cycles", s->cycles);
			if (rte_tel_data_add_dict_container(d, s->name, val, 0) != 0) {
				rte_tel_data_free(val);
				goto err;
			}
		}
	}

	gr_vec_free(stats);
	return 0;
err:
	gr_vec_free(stats);
	return -1;
}

static int
telemetry_ifaces_info_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	struct iface *iface = NULL;

	rte_tel_data_start_dict(d);

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		if (iface->type != GR_IFACE_TYPE_LOOPBACK) {
			struct rte_tel_data *iface_container = rte_tel_data_alloc();
			if (iface_container == NULL) {
				goto err;
			}
			rte_tel_data_start_dict(iface_container);

			rte_tel_data_add_dict_string(iface_container, "name", iface->name);
			rte_tel_data_add_dict_uint(iface_container, "id", iface->id);
			rte_tel_data_add_dict_string(
				iface_container, "type", gr_iface_type_name(iface->type)
			);
			rte_tel_data_add_dict_uint(iface_container, "mtu", iface->mtu);

			struct rte_tel_data *flags_array = rte_tel_data_alloc();
			if (flags_array == NULL) {
				rte_tel_data_free(iface_container);
				goto err;
			}
			rte_tel_data_start_array(flags_array, RTE_TEL_STRING_VAL);
			if (iface->flags & GR_IFACE_F_UP)
				rte_tel_data_add_array_string(flags_array, "up");
			if (iface->state & GR_IFACE_S_RUNNING)
				rte_tel_data_add_array_string(flags_array, "running");
			rte_tel_data_add_dict_container(iface_container, "flags", flags_array, 0);

			rte_tel_data_add_dict_string(
				iface_container, "mode", gr_iface_mode_name(iface->mode)
			);
			rte_tel_data_add_dict_uint(iface_container, "vrf_id", iface->vrf_id);

			struct rte_tel_data *stats_container = rte_tel_data_alloc();
			if (stats_container == NULL) {
				rte_tel_data_free(iface_container);
				goto err;
			}
			rte_tel_data_start_dict(stats_container);

			// Software stats
			uint64_t rx_pkts = 0, rx_bytes = 0, tx_pkts = 0, tx_bytes = 0;
			for (int i = 0; i < RTE_MAX_LCORE; i++) {
				struct iface_stats *sw_stats = iface_get_stats(i, iface->id);
				rx_pkts += sw_stats->rx_packets;
				rx_bytes += sw_stats->rx_bytes;
				tx_pkts += sw_stats->tx_packets;
				tx_bytes += sw_stats->tx_bytes;
			}
			rte_tel_data_add_dict_uint(stats_container, "rx_packets", rx_pkts);
			rte_tel_data_add_dict_uint(stats_container, "rx_bytes", rx_bytes);
			rte_tel_data_add_dict_uint(stats_container, "tx_packets", tx_pkts);
			rte_tel_data_add_dict_uint(stats_container, "tx_bytes", tx_bytes);

			// Get hardware stats for physical ports.
			if (iface->type == GR_IFACE_TYPE_PORT) {
				struct iface_info_port *port = iface_info_port(iface);

				struct rte_eth_stats eth_stats;
				if (rte_eth_stats_get(port->port_id, &eth_stats) == 0) {
					rte_tel_data_add_dict_uint(
						stats_container, "rx_missed", eth_stats.imissed
					);
					rte_tel_data_add_dict_uint(
						stats_container, "tx_errors", eth_stats.oerrors
					);
				}

				int ret = rte_eth_xstats_get(port->port_id, NULL, 0);
				if (ret > 0) {
					unsigned num = ret;
					struct rte_eth_xstat *xstats = calloc(num, sizeof(*xstats));
					struct rte_eth_xstat_name *names = calloc(
						num, sizeof(*names)
					);
					if (xstats != NULL && names != NULL
					    && rte_eth_xstats_get_names(port->port_id, names, num)
						    == (int)num
					    && rte_eth_xstats_get(port->port_id, xstats, num)
						    == (int)num) {
						for (unsigned i = 0; i < num; i++) {
							if (xstats[i].value > 0) {
								rte_tel_data_add_dict_uint(
									stats_container,
									names[i].name,
									xstats[i].value
								);
							}
						}
					}
					free(xstats);
					free(names);
				}

				if (rte_tel_data_add_dict_container(
					    iface_container, "statistics", stats_container, 0
				    )
				    != 0) {
					rte_tel_data_free(stats_container);
					rte_tel_data_free(iface_container);
					goto err;
				}
			}

			if (rte_tel_data_add_dict_container(d, iface->name, iface_container, 0)
			    != 0) {
				rte_tel_data_free(iface_container);
				goto err;
			}
		}
	}
	return 0;

err:
	return -1;
}

static struct gr_api_handler stats_get_handler = {
	.name = "stats get",
	.request_type = GR_INFRA_STATS_GET,
	.callback = stats_get,
};

static struct gr_api_handler stats_reset_handler = {
	.name = "stats reset",
	.request_type = GR_INFRA_STATS_RESET,
	.callback = stats_reset,
};

static struct gr_api_handler iface_stats_get_handler = {
	.name = "iface stats get",
	.request_type = GR_INFRA_IFACE_STATS_GET,
	.callback = iface_stats_get,
};

RTE_INIT(infra_stats_init) {
	gr_register_api_handler(&stats_get_handler);
	gr_register_api_handler(&stats_reset_handler);
	gr_register_api_handler(&iface_stats_get_handler);
	rte_telemetry_register_cmd(
		"/grout/stats/graph",
		telemetry_sw_stats_get,
		"Returns statistics of each graph node. No parameters"
	);
	rte_telemetry_register_cmd(
		"/grout/iface",
		telemetry_ifaces_info_get,
		"Returns information per interface. No parameters"
	);
}
