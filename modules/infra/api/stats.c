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

struct stat_entry {
	char *key;
	uint64_t value;
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
		LIST_FOREACH (worker, &workers, next) {
			const struct worker_stats *w_stats = atomic_load(&worker->stats);
			if (w_stats == NULL)
				continue;
			for (unsigned i = 0; i < w_stats->n_stats; i++) {
				const struct node_stats *s = &w_stats->stats[i];
				const char *name = rte_node_id_to_name(s->node_id);
				struct stat_entry *e = shgetp_null(smap, name);
				if (e != NULL) {
					e->value += s->objs;
				} else {
					shput(smap, name, s->objs);
				}
			}
		}
	}

	if (req->flags & BR_INFRA_STAT_F_HW) {
		struct rte_eth_stats rte_stats;
		struct rte_eth_dev_info info;
		struct port *port;

#define hw_stat(field)                                                                             \
	do {                                                                                       \
		snprintf(name, sizeof(name), "p%u.%s", port->port_id, #field);                     \
		shput(smap, name, rte_stats.field);                                                \
	} while (0)
#define q_stat(q, dir, field)                                                                      \
	do {                                                                                       \
		snprintf(name, sizeof(name), "p%u.%sq%u.%s", port->port_id, dir, q, #field);       \
		shput(smap, name, rte_stats.q_##field[q]);                                         \
	} while (0)

		LIST_FOREACH (port, &ports, next) {
			if ((ret = rte_eth_stats_get(port->port_id, &rte_stats)) < 0)
				goto err;
			if ((ret = rte_eth_dev_info_get(port->port_id, &info)) < 0)
				goto err;

			hw_stat(ipackets);
			hw_stat(opackets);
			hw_stat(ibytes);
			hw_stat(obytes);
			hw_stat(imissed);
			hw_stat(ierrors);
			hw_stat(oerrors);
			hw_stat(rx_nombuf);

			for (unsigned q = 0; q < info.nb_rx_queues; q++) {
				q_stat(q, "rx", ipackets);
				q_stat(q, "rx", ibytes);
				q_stat(q, "rx", errors);
			}
			for (unsigned q = 0; q < info.nb_tx_queues; q++) {
				q_stat(q, "tx", opackets);
				q_stat(q, "tx", obytes);
			}
		}
#undef hw_stat
#undef q_stat
	}

	if (req->flags & BR_INFRA_STAT_F_XHW) {
		struct rte_eth_xstat_name *names = NULL;
		struct rte_eth_xstat *xstats = NULL;
		struct port *port;
		unsigned num;

		LIST_FOREACH (port, &ports, next) {
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
				// prefix each xstat name with 'p${PORT_ID}.'
				snprintf(
					name, sizeof(name), "p%u.%s", port->port_id, names[i].name
				);
				shput(smap, name, xstats[i].value);
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
		if (e->value == 0 && !(req->flags & BR_INFRA_STAT_F_ZERO))
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
		if (e->value == 0 && !(req->flags & BR_INFRA_STAT_F_ZERO))
			continue;
		switch (fnmatch(req->pattern, e->key, 0)) {
		case 0:
			s = &resp->stats[resp->n_stats++];
			memccpy(s->name, e->key, 0, sizeof(s->name));
			s->value = e->value;
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
	struct port *port;
	int ret;

	(void)request;
	(void)response;

	LIST_FOREACH (worker, &workers, next)
		atomic_store(&worker->stats_reset, true);
	LIST_FOREACH (port, &ports, next) {
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
