// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_control.h>
#include <gr_ip6_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_nh_control.h>
#include <gr_port.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_telemetry.h>

#include <fnmatch.h>
#include <stdatomic.h>

struct stat {
	char name[64];
	uint64_t objs;
	uint64_t calls;
	uint64_t cycles;
};

static struct stat *find_stat(struct stat *stats, const char *name) {
	struct stat *s;

	gr_vec_foreach_ref (s, stats) {
		if (strncmp(s->name, name, sizeof(s->name)) == 0)
			return s;
	}

	return errno_set_null(ENOENT);
}

static struct api_out stats_get(const void *request, void **response) {
	const struct gr_infra_stats_get_req *req = request;
	struct gr_infra_stats_get_resp *resp = NULL;
	struct stat *stats = NULL, *s;
	size_t len, n_stats;
	int ret;

	if (req->flags & GR_INFRA_STAT_F_SW) {
		struct worker *worker;

		STAILQ_FOREACH (worker, &workers, next) {
			const struct worker_stats *w_stats = atomic_load(&worker->stats);
			if (w_stats == NULL)
				continue;
			for (unsigned i = 0; i < w_stats->n_stats; i++) {
				const struct node_stats *n = &w_stats->stats[i];
				const char *name = rte_node_id_to_name(n->node_id);
				s = find_stat(stats, name);
				if (s != NULL) {
					s->objs += n->objs;
					s->calls += n->calls;
					s->cycles += n->cycles;
				} else {
					struct stat stat = {
						.objs = n->objs,
						.calls = n->calls,
						.cycles = n->cycles,
					};
					memccpy(stat.name, name, 0, sizeof(stat.name));
					gr_vec_add(stats, stat);
				}
			}
			s = find_stat(stats, "idle");
			if (s != NULL) {
				s->calls += w_stats->n_sleeps;
				s->cycles += w_stats->sleep_cycles;
			} else {
				struct stat stat = {
					.objs = 0,
					.calls = w_stats->n_sleeps,
					.cycles = w_stats->sleep_cycles,
				};
				memccpy(stat.name, "idle", 0, sizeof(stat.name));
				gr_vec_add(stats, stat);
			}
		}
	}

	if (req->flags & GR_INFRA_STAT_F_HW) {
		struct rte_eth_xstat_name *names = NULL;
		struct rte_eth_xstat *xstats = NULL;
		struct iface *iface = NULL;
		unsigned num;

		while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
			struct iface_info_port *port = (struct iface_info_port *)iface->info;

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
				struct stat stat = {
					.objs = xstats[i].value,
					.calls = 0,
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
		if (s->objs == 0 && !(req->flags & GR_INFRA_STAT_F_ZERO))
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
		struct gr_infra_stat *i;
		if (s->objs == 0 && !(req->flags & GR_INFRA_STAT_F_ZERO))
			continue;
		switch (fnmatch(req->pattern, s->name, 0)) {
		case 0:
			i = &resp->stats[resp->n_stats++];
			memccpy(i->name, s->name, 0, sizeof(i->name));
			i->objs = s->objs;
			i->calls = s->calls;
			i->cycles = s->cycles;
		case FNM_NOMATCH:
			continue;
		default:
			ret = -errno;
			goto err;
		}
	}

	gr_vec_free(stats);
	*response = resp;
	return api_out(0, len);
err:
	gr_vec_free(stats);
	free(resp);
	return api_out(-ret, 0);
}

#define VRF_ID_STR_SIZE 11

static struct api_out stats_reset(const void * /*request*/, void ** /*response*/) {
	struct worker *worker;
	struct iface *iface;
	int ret;

	STAILQ_FOREACH (worker, &workers, next) {
		atomic_store(&worker->stats_reset, true);
		worker_signal_ready(worker);
	}

	iface = NULL;

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		struct iface_stats *sw_stats = iface_get_stats(iface->id);
		// Reset software stats for all interface types.
		if (sw_stats != NULL) {
			memset(sw_stats, 0, sizeof(*sw_stats));
		}

		if (iface->type == GR_IFACE_TYPE_PORT) {
			struct iface_info_port *port = (struct iface_info_port *)iface->info;
			if ((ret = rte_eth_stats_reset(port->port_id)) < 0)
				return api_out(-ret, 0);
			if ((ret = rte_eth_xstats_reset(port->port_id)) < 0)
				return api_out(-ret, 0);
		}
	}

	return api_out(0, 0);
}

static struct api_out iface_stats_get(const void * /*request*/, void **response) {
	struct gr_infra_iface_stats_get_resp *resp = NULL;
	struct gr_iface_stats *stats_vec = NULL;
	struct iface *iface = NULL;
	int ret = 0;

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		struct iface_stats *sw_stats = iface_get_stats(iface->id);
		if (sw_stats == NULL)
			continue;

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
			s.rx_packets += sw_stats->rx_packets[i];
			s.rx_bytes += sw_stats->rx_bytes[i];
			s.tx_packets += sw_stats->tx_packets[i];
			s.tx_bytes += sw_stats->tx_bytes[i];
		}

		if (iface->type == GR_IFACE_TYPE_PORT) {
			// If possible, use the hardware statistics from the driver
			struct iface_info_port *port = (struct iface_info_port *)iface->info;
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
	memcpy(resp->stats, stats_vec, n_stats * sizeof(struct gr_iface_stats));

	gr_vec_free(stats_vec);
	*response = resp;
	return api_out(0, len);
err:
	gr_vec_free(stats_vec);
	free(resp);
	return api_out(-ret, 0);
}

static int
telemetry_sw_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	struct stat *stats = NULL, *s;
	struct worker *worker;

	rte_tel_data_start_dict(d);

	STAILQ_FOREACH (worker, &workers, next) {
		const struct worker_stats *w_stats = atomic_load(&worker->stats);
		if (w_stats == NULL)
			continue;
		for (unsigned i = 0; i < w_stats->n_stats; i++) {
			const struct node_stats *n = &w_stats->stats[i];
			const char *name = rte_node_id_to_name(n->node_id);
			s = find_stat(stats, name);
			if (s != NULL) {
				s->objs += n->objs;
				s->calls += n->calls;
				s->cycles += n->cycles;
			} else {
				struct stat stat = {
					.objs = n->objs,
					.calls = n->calls,
					.cycles = n->cycles,
				};
				memccpy(stat.name, name, 0, sizeof(stat.name));
				gr_vec_add(stats, stat);
			}
		}
		s = find_stat(stats, "idle");
		if (s != NULL) {
			s->calls += w_stats->n_sleeps;
			s->cycles += w_stats->sleep_cycles;
		} else {
			struct stat stat = {
				.objs = 0,
				.calls = w_stats->n_sleeps,
				.cycles = w_stats->sleep_cycles,
			};
			memccpy(stat.name, "idle", 0, sizeof(stat.name));
			gr_vec_add(stats, stat);
		}
	}
	gr_vec_foreach_ref (s, stats) {
		if (s->calls > 0) {
			struct rte_tel_data *val = rte_tel_data_alloc();
			if (val == NULL) {
				goto err;
			}
			rte_tel_data_start_dict(val);
			rte_tel_data_add_dict_uint(val, "packets", s->objs);
			rte_tel_data_add_dict_uint(val, "calls", s->calls);
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
				iface_container, "type", iface_type_to_str(iface->type)
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
				iface_container, "mode", iface_mode_to_str(iface->mode)
			);
			rte_tel_data_add_dict_uint(iface_container, "vrf_id", iface->vrf_id);

			struct rte_tel_data *stats_container = rte_tel_data_alloc();
			if (stats_container == NULL) {
				rte_tel_data_free(iface_container);
				goto err;
			}
			rte_tel_data_start_dict(stats_container);

			// Software stats
			struct iface_stats *sw_stats = iface_get_stats(iface->id);
			if (sw_stats != NULL) {
				uint64_t rx_pkts = 0, rx_bytes = 0, tx_pkts = 0, tx_bytes = 0;
				for (int i = 0; i < RTE_MAX_LCORE; i++) {
					rx_pkts += sw_stats->rx_packets[i];
					rx_bytes += sw_stats->rx_bytes[i];
					tx_pkts += sw_stats->tx_packets[i];
					tx_bytes += sw_stats->tx_bytes[i];
				}
				rte_tel_data_add_dict_uint(stats_container, "rx_packets", rx_pkts);
				rte_tel_data_add_dict_uint(stats_container, "rx_bytes", rx_bytes);
				rte_tel_data_add_dict_uint(stats_container, "tx_packets", tx_pkts);
				rte_tel_data_add_dict_uint(stats_container, "tx_bytes", tx_bytes);
			}

			// Get hardware stats for physical ports.
			if (iface->type == GR_IFACE_TYPE_PORT) {
				struct iface_info_port *port = (struct
								iface_info_port *)iface->info;

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

static int
telemetry_rib_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	rte_tel_data_start_dict(d);

	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		struct rib4_stats *rib4_stats = rib4_get_stats(vrf_id);
		struct rib6_stats *rib6_stats = rib6_get_stats(vrf_id);

		// Skip VRFs that don't have any routes
		uint32_t total_routes = 0;
		if (rib4_stats)
			total_routes += atomic_load(&rib4_stats->total_routes);
		if (rib6_stats)
			total_routes += atomic_load(&rib6_stats->total_routes);

		if (total_routes == 0)
			continue;

		// Create VRF container with VRF ID as key
		char vrf_key[VRF_ID_STR_SIZE];
		snprintf(vrf_key, sizeof(vrf_key), "vrf_%u", vrf_id);

		struct rte_tel_data *vrf_data = rte_tel_data_alloc();
		if (vrf_data == NULL) {
			goto err;
		}
		rte_tel_data_start_dict(vrf_data);

		rte_tel_data_add_dict_uint(vrf_data, "vrf_id", vrf_id);

		struct rte_tel_data *ipv4_data = NULL;
		struct rte_tel_data *ipv6_data = NULL;

		// Allocate and build IPv4 container if needed
		if (rib4_stats && atomic_load(&rib4_stats->total_routes) > 0) {
			ipv4_data = rte_tel_data_alloc();
			if (ipv4_data == NULL) {
				rte_tel_data_free(vrf_data);
				goto err;
			}
			rte_tel_data_start_dict(ipv4_data);

			rte_tel_data_add_dict_uint(
				ipv4_data, "total", atomic_load(&rib4_stats->total_routes)
			);

			// Add route counts by origin (only non-zero counts)
			for (int i = 0; i <= GR_NH_ORIGIN_MAX; i++) {
				uint32_t count = atomic_load(&rib4_stats->by_origin[i]);
				if (count > 0) {
					const char *origin_name = gr_nh_origin_name(i);
					rte_tel_data_add_dict_uint(ipv4_data, origin_name, count);
				}
			}
		}

		// Allocate and build IPv6 container if needed
		if (rib6_stats && atomic_load(&rib6_stats->total_routes) > 0) {
			ipv6_data = rte_tel_data_alloc();
			if (ipv6_data == NULL) {
				rte_tel_data_free(ipv4_data);
				rte_tel_data_free(vrf_data);
				goto err;
			}
			rte_tel_data_start_dict(ipv6_data);

			rte_tel_data_add_dict_uint(
				ipv6_data, "total", atomic_load(&rib6_stats->total_routes)
			);

			// Add route counts by origin (only non-zero counts)
			for (int i = 0; i <= GR_NH_ORIGIN_MAX; i++) {
				uint32_t count = atomic_load(&rib6_stats->by_origin[i]);
				if (count > 0) {
					const char *origin_name = gr_nh_origin_name(i);
					rte_tel_data_add_dict_uint(ipv6_data, origin_name, count);
				}
			}
		}

		// Now add completed containers to vrf_data
		if (ipv4_data != NULL) {
			if (rte_tel_data_add_dict_container(vrf_data, "ipv4", ipv4_data, 0) != 0) {
				rte_tel_data_free(ipv4_data);
				rte_tel_data_free(ipv6_data);
				rte_tel_data_free(vrf_data);
				goto err;
			}
		}

		if (ipv6_data != NULL) {
			if (rte_tel_data_add_dict_container(vrf_data, "ipv6", ipv6_data, 0) != 0) {
				rte_tel_data_free(ipv4_data);
				rte_tel_data_free(ipv6_data);
				rte_tel_data_free(vrf_data);
				goto err;
			}
		}

		if (rte_tel_data_add_dict_container(d, vrf_key, vrf_data, 0) != 0) {
			rte_tel_data_free(vrf_data);
			goto err;
		}
	}

	return 0;

err:
	return -1;
}

static int
telemetry_nexthop_stats_get(const char * /*cmd*/, const char * /*params*/, struct rte_tel_data *d) {
	// Use dictionary with VRF indices as keys to simulate array behavior
	rte_tel_data_start_dict(d);

	for (uint16_t vrf_id = 0; vrf_id < MAX_VRFS; vrf_id++) {
		struct nh_stats *nh4_stats = nexthop_get_stats(vrf_id, GR_AF_IP4);
		struct nh_stats *nh6_stats = nexthop_get_stats(vrf_id, GR_AF_IP6);

		// Skip VRFs that don't have any nexthops
		uint32_t total_nexthops = 0;
		if (nh4_stats)
			total_nexthops += atomic_load(&nh4_stats->total);
		if (nh6_stats)
			total_nexthops += atomic_load(&nh6_stats->total);
		if (total_nexthops == 0)
			continue;

		// Create VRF container with VRF ID as key
		char vrf_key[VRF_ID_STR_SIZE];
		snprintf(vrf_key, sizeof(vrf_key), "vrf_%u", vrf_id);

		struct rte_tel_data *vrf_data = rte_tel_data_alloc();
		if (vrf_data == NULL) {
			goto err;
		}
		rte_tel_data_start_dict(vrf_data);

		rte_tel_data_add_dict_uint(vrf_data, "vrf_id", vrf_id);

		// Add nexthop counts by address family
		if (nh4_stats) {
			rte_tel_data_add_dict_uint(
				vrf_data, "ipv4", atomic_load(&nh4_stats->total)
			);
		}
		if (nh6_stats) {
			rte_tel_data_add_dict_uint(
				vrf_data, "ipv6", atomic_load(&nh6_stats->total)
			);
		}

		// Add nexthop counts by state (aggregate across both address families)
		uint32_t state_counts[GR_NH_STATE_COUNT] = {0};
		if (nh4_stats) {
			for (int i = 0; i < GR_NH_STATE_COUNT; i++) {
				state_counts[i] += atomic_load(&nh4_stats->by_state[i]);
			}
		}
		if (nh6_stats) {
			for (int i = 0; i < GR_NH_STATE_COUNT; i++) {
				state_counts[i] += atomic_load(&nh6_stats->by_state[i]);
			}
		}

		// Add state counts (only non-zero counts)
		for (int i = 0; i < GR_NH_STATE_COUNT; i++) {
			if (state_counts[i] > 0) {
				struct gr_nexthop temp_nh = {.state = i};
				const char *state_name = gr_nh_state_name(&temp_nh);
				rte_tel_data_add_dict_uint(vrf_data, state_name, state_counts[i]);
			}
		}

		if (rte_tel_data_add_dict_container(d, vrf_key, vrf_data, 0) != 0) {
			rte_tel_data_free(vrf_data);
			goto err;
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
	rte_telemetry_register_cmd(
		"/grout/rib/stats",
		telemetry_rib_stats_get,
		"Returns RIB (route) statistics per VRF. No parameters"
	);
	rte_telemetry_register_cmd(
		"/grout/nexthop/stats",
		telemetry_nexthop_stats_get,
		"Returns nexthop statistics per VRF. No parameters"
	);
}
