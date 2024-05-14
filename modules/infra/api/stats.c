// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <br_api.h>
#include <br_control.h>
#include <br_infra.h>
#include <br_log.h>
#include <br_port.h>
#include <br_stb_ds.h>
#include <br_worker.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>

#include <fnmatch.h>

struct stat_value {
	uint64_t objs;
	uint64_t calls;
	uint64_t cycles;
};

struct stat_entry {
	char *key;
	struct stat_value value;
};

static struct api_out stats_get(const void *request, void **response) {
	const struct br_infra_stats_get_req *req = request;
	struct br_infra_stats_get_resp *resp = NULL;
	struct stat_entry *smap = NULL;
	size_t len, n_stats;
	char name[64];
	int ret;

	sh_new_arena(smap);

	if (req->flags & BR_INFRA_STAT_F_SW) {
		struct worker *worker;

		STAILQ_FOREACH (worker, &workers, next) {
			const struct worker_stats *w_stats = atomic_load(&worker->stats);
			if (w_stats == NULL)
				continue;
			for (unsigned i = 0; i < w_stats->n_stats; i++) {
				const struct node_stats *s = &w_stats->stats[i];
				const char *name = rte_node_id_to_name(s->node_id);
				struct stat_entry *e = shgetp_null(smap, name);
				if (e != NULL) {
					e->value.objs += s->objs;
					e->value.calls += s->calls;
					e->value.cycles += s->cycles;
				} else {
					struct stat_value value = {
						.objs = s->objs,
						.calls = s->calls,
						.cycles = s->cycles,
					};
					shput(smap, name, value);
				}
			}
		}
	}

	if (req->flags & BR_INFRA_STAT_F_HW) {
		struct rte_eth_xstat_name *names = NULL;
		struct rte_eth_xstat *xstats = NULL;
		struct iface *iface = NULL;
		unsigned num;

		while ((iface = iface_next(IFACE_TYPE_PORT, iface)) != NULL) {
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
				struct stat_value value = {.objs = xstats[i].value};
				// prefix each xstat name with interface name
				snprintf(name, sizeof(name), "%s.%s", iface->name, names[i].name);
				shput(smap, name, value);
			}
free_xstat:
			free(xstats);
			free(names);
			if (ret < 0)
				goto err;
		}
	}

	// iterate once to determine the number of stats matching pattern
	n_stats = 0;
	for (unsigned i = 0; i < shlenu(smap); i++) {
		struct stat_entry *e = &smap[i];
		if (e->value.objs == 0 && !(req->flags & BR_INFRA_STAT_F_ZERO))
			continue;
		switch (fnmatch(req->pattern, e->key, 0)) {
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
	len = sizeof(*resp) + n_stats * sizeof(struct br_infra_stat);
	if ((resp = calloc(1, len)) == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	// fill in response
	for (unsigned i = 0; i < shlenu(smap); i++) {
		struct stat_entry *e = &smap[i];
		struct br_infra_stat *s;
		if (e->value.objs == 0 && !(req->flags & BR_INFRA_STAT_F_ZERO))
			continue;
		switch (fnmatch(req->pattern, e->key, 0)) {
		case 0:
			s = &resp->stats[resp->n_stats++];
			memccpy(s->name, e->key, 0, sizeof(s->name));
			s->objs = e->value.objs;
			s->calls = e->value.calls;
			s->cycles = e->value.cycles;
		case FNM_NOMATCH:
			continue;
		default:
			ret = -errno;
			goto err;
		}
	}

	shfree(smap);
	*response = resp;
	return api_out(0, len);
err:
	shfree(smap);
	free(resp);
	return api_out(-ret, 0);
}

static struct api_out stats_reset(const void *request, void **response) {
	struct worker *worker;
	struct iface *iface;
	int ret;

	(void)request;
	(void)response;

	STAILQ_FOREACH (worker, &workers, next)
		atomic_store(&worker->stats_reset, true);

	iface = NULL;
	while ((iface = iface_next(IFACE_TYPE_PORT, iface)) != NULL) {
		struct iface_info_port *port = (struct iface_info_port *)iface->info;
		if ((ret = rte_eth_stats_reset(port->port_id)) < 0)
			return api_out(-ret, 0);
		if ((ret = rte_eth_xstats_reset(port->port_id)) < 0)
			return api_out(-ret, 0);
	}

	return api_out(0, 0);
}

static struct br_api_handler stats_get_handler = {
	.name = "stats get",
	.request_type = BR_INFRA_STATS_GET,
	.callback = stats_get,
};

static struct br_api_handler stats_reset_handler = {
	.name = "stats reset",
	.request_type = BR_INFRA_STATS_RESET,
	.callback = stats_reset,
};

RTE_INIT(infra_stats_init) {
	br_register_api_handler(&stats_get_handler);
	br_register_api_handler(&stats_reset_handler);
}
