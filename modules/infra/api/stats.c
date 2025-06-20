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

static struct api_out stats_reset(const void * /*request*/, void ** /*response*/) {
	struct worker *worker;
	struct iface *iface;
	int ret;

	STAILQ_FOREACH (worker, &workers, next) {
		atomic_store(&worker->stats_reset, true);
		worker_signal_ready(worker);
	}

	iface = NULL;
	while ((iface = iface_next(GR_IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *port = (struct iface_info_port *)iface->info;
		if ((ret = rte_eth_stats_reset(port->port_id)) < 0)
			return api_out(-ret, 0);
		if ((ret = rte_eth_xstats_reset(port->port_id)) < 0)
			return api_out(-ret, 0);
	}

	return api_out(0, 0);
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

RTE_INIT(infra_stats_init) {
	gr_register_api_handler(&stats_get_handler);
	gr_register_api_handler(&stats_reset_handler);
	rte_telemetry_register_cmd(
		"/grout/stats/graph",
		telemetry_sw_stats_get,
		"Returns statistics of each graph node. No parameters"
	);
}
