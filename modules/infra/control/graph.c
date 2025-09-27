// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include "graph_priv.h"

#include <gr_datapath.h>
#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_queue.h>
#include <gr_rxtx.h>
#include <gr_string.h>
#include <gr_vec.h>
#include <gr_worker.h>

#include <event2/event.h>
#include <rte_build_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <stdatomic.h>
#include <sys/queue.h>
#include <unistd.h>

struct node_infos node_infos = STAILQ_HEAD_INITIALIZER(node_infos);
static gr_vec const char **base_node_names;
static gr_vec char **rx_node_names;
static gr_vec char **tx_node_names;
static rte_node_t port_rx_node;
static rte_node_t port_tx_node;
static rte_node_t port_output_node;

rte_edge_t gr_node_attach_parent(const char *parent, const char *node) {
	rte_node_t parent_id;
	rte_edge_t edge;
	char **names;

	if ((parent_id = rte_node_from_name(parent)) == RTE_NODE_ID_INVALID)
		ABORT("'%s' parent node not found", parent);

	edge = rte_node_edge_update(parent_id, RTE_EDGE_ID_INVALID, &node, 1);
	if (edge == RTE_EDGE_ID_INVALID)
		ABORT("rte_node_edge_update: %s", rte_strerror(rte_errno));

	names = calloc(rte_node_edge_count(parent_id), sizeof(char *));
	if (names == NULL)
		ABORT("calloc(rte_node_edge_count('%s')) failed", parent);
	if (rte_node_edge_get(parent_id, names) == RTE_EDGE_ID_INVALID)
		ABORT("rte_node_edge_get('%s')) failed", parent);
	for (edge = 0; edge < rte_node_edge_count(parent_id); edge++) {
		if (strcmp(names[edge], node) == 0)
			break;
	}
	free(names);
	if (edge == rte_node_edge_count(parent_id))
		ABORT("cannot find added edge");

	LOG(DEBUG, "attach %s -> %s (edge=%u)", parent, node, edge);

	return edge;
}

void worker_graph_free(struct worker *worker) {
	int ret;
	for (int i = 0; i < 2; i++) {
		if (worker->graph[i] != NULL) {
			if ((ret = rte_graph_destroy(worker->graph[i]->id)) < 0)
				LOG(ERR, "rte_graph_destroy: %s", rte_strerror(-ret));
			worker->graph[i] = NULL;
		}
	}
}

static int
worker_graph_new(struct worker *worker, uint8_t index, gr_vec struct iface_info_port **ports) {
	gr_vec const char **graph_nodes = NULL;
	char graph_name[RTE_GRAPH_NAMESIZE];
	char node_name[RTE_NODE_NAMESIZE];
	gr_vec char **rx_nodes = NULL;
	struct queue_map *qmap;
	struct rte_node *node;
	uint16_t graph_uid;
	unsigned n_rxqs;
	int ret = 0;

	n_rxqs = 0;
	gr_vec_foreach_ref (qmap, worker->rxqs) {
		if (qmap->enabled)
			n_rxqs++;
	}
	if (n_rxqs == 0) {
		worker->graph[index] = NULL;
		return 0;
	}

	// unique suffix for this graph
	graph_uid = (worker->cpu_id << 1) | (0x1 & index);
	snprintf(graph_name, sizeof(graph_name), "gr-%04x", graph_uid);

	// generate graph nodes list
	gr_vec_foreach_ref (qmap, worker->rxqs) {
		if (!qmap->enabled)
			continue;
		LOG(DEBUG,
		    "[CPU %d] <- port %u rxq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);

		char *name = astrcat(NULL, RX_NODE_FMT, qmap->port_id, qmap->queue_id);
		gr_vec_add(rx_nodes, name);
		gr_vec_add(graph_nodes, name);
	}

	gr_vec_extend(graph_nodes, base_node_names);
	gr_vec_extend(graph_nodes, tx_node_names);

	// graph init
	struct rte_graph_param params = {
		.socket_id = rte_lcore_to_socket_id(worker->lcore_id),
		.nb_node_patterns = gr_vec_len(graph_nodes),
		.node_patterns = graph_nodes,
	};
	if (rte_graph_create(graph_name, &params) == RTE_GRAPH_ID_INVALID) {
		if (rte_errno == 0)
			rte_errno = EINVAL;
		ret = -rte_errno;
		goto out;
	}
	worker->graph[index] = rte_graph_lookup(graph_name);

	// set rx nodes context data
	gr_vec_foreach_ref (qmap, worker->rxqs) {
		if (!qmap->enabled)
			continue;
		snprintf(node_name, sizeof(node_name), RX_NODE_FMT, qmap->port_id, qmap->queue_id);
		node = rte_graph_node_get_by_name(graph_name, node_name);
		struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
		gr_vec_foreach (struct iface_info_port *p, ports) {
			if (p->port_id == qmap->port_id) {
				ctx->iface = RTE_PTR_SUB(p, offsetof(struct iface, info));
				break;
			}
		}
		assert(ctx->iface != NULL);
		ctx->rxq.port_id = qmap->port_id;
		ctx->rxq.queue_id = qmap->queue_id;
		ctx->burst_size = RTE_GRAPH_BURST_SIZE / gr_vec_len(worker->rxqs);
	}

	// initialize all tx nodes context to invalid ports and queues
	gr_vec_foreach (const char *name, tx_node_names) {
		node = rte_graph_node_get_by_name(graph_name, name);
		struct port_queue *ctx = (struct port_queue *)node->ctx;
		ctx->port_id = UINT16_MAX;
		ctx->queue_id = UINT16_MAX;
	}

	// initialize the port_output node context to point to invalid edges
	struct port_output_edges *out = rte_malloc(__func__, sizeof(*out), RTE_CACHE_LINE_SIZE);
	if (out == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	for (unsigned i = 0; i < ARRAY_DIM(out->edges); i++)
		out->edges[i] = RTE_EDGE_ID_INVALID;

	gr_vec_foreach_ref (qmap, worker->txqs) {
		if (!qmap->enabled)
			continue;
		LOG(DEBUG,
		    "[CPU %d] -> port %u txq %u",
		    worker->cpu_id,
		    qmap->port_id,
		    qmap->queue_id);
		// find the corresponding port_tx clone for this port-txq pair
		snprintf(node_name, sizeof(node_name), TX_NODE_FMT, qmap->port_id, qmap->queue_id);
		node = rte_graph_node_get_by_name(graph_name, node_name);
		// and update its context data to correct values
		struct port_queue *ctx = (struct port_queue *)node->ctx;
		ctx->port_id = qmap->port_id;
		ctx->queue_id = qmap->queue_id;

		for (rte_edge_t edge = 0; edge < gr_vec_len(tx_node_names); edge++) {
			if (strcmp(tx_node_names[edge], node_name) == 0) {
				// update the port_output context data to map this port to the
				// correct edge
				out->edges[ctx->port_id] = edge;
				break;
			}
		}
	}

	// finally, set the port_output context data
	rte_graph_node_get_by_name(graph_name, "port_output")->ctx_ptr = out;

out:
	gr_vec_free(graph_nodes);
	gr_strvec_free(rx_nodes);

	return errno_set(-ret);
}

int worker_graph_reload(struct worker *worker, gr_vec struct iface_info_port **ports) {
	unsigned next = !atomic_load(&worker->cur_config);
	int ret;

	if ((ret = worker_graph_new(worker, next, ports)) < 0)
		return errno_log(-ret, "worker_graph_new");

	// wait for datapath worker to pickup the config update
	atomic_store(&worker->next_config, next);
	worker_signal_ready(worker);
	while (atomic_load(&worker->cur_config) != next)
		usleep(500);

	// free old config
	next = !next;

	if (worker->graph[next] != NULL) {
		if ((ret = rte_graph_destroy(worker->graph[next]->id)) < 0)
			errno_log(-ret, "rte_graph_destroy");
		worker->graph[next] = NULL;
	}

	return 0;
}

static char *ensure_queue_node(
	rte_node_t base_node,
	const char *name_fmt,
	uint16_t port_id,
	uint16_t queue_id,
	gr_vec char **old_list
) {
	char *name = astrcat(NULL, name_fmt, port_id, queue_id);
	assert(name != NULL);

	// remove node from the old list so that only unused nodes remain
	for (unsigned i = 0; i < gr_vec_len(old_list); i++) {
		if (strcmp(old_list[i], name) == 0) {
			free(old_list[i]);
			gr_vec_del(old_list, i);
			break;
		}
	}
	if (rte_node_from_name(name) == RTE_NODE_ID_INVALID) {
		// node does not exist yet, clone it from the base
		rte_node_t node = rte_node_clone(base_node, strstr(name, "-") + 1);
		assert(node != RTE_NODE_ID_INVALID);
	}

	return name;
}

static gr_vec rte_node_t *worker_graph_nodes_add_missing(gr_vec struct iface_info_port **ports) {
	gr_vec char **old_rx = gr_vec_clone(rx_node_names);
	gr_vec char **old_tx = gr_vec_clone(tx_node_names);
	rte_node_t *unused_nodes = NULL;
	rte_edge_t edge;
	char *name;

	gr_vec_free(rx_node_names);
	gr_vec_free(tx_node_names);

	// clone port_rx and port_tx to match all possible port-queue pairs
	gr_vec_foreach (struct iface_info_port *port, ports) {
		for (uint16_t rxq = 0; rxq < port->n_rxq; rxq++) {
			name = ensure_queue_node(
				port_rx_node, RX_NODE_FMT, port->port_id, rxq, old_rx
			);
			gr_vec_add(rx_node_names, name);
		}
		for (uint16_t txq = 0; txq < port->n_txq; txq++) {
			name = ensure_queue_node(
				port_tx_node, TX_NODE_FMT, port->port_id, txq, old_tx
			);
			gr_vec_add(tx_node_names, name);
		}
	}

	// update the port_output edges to allow reaching all possible port_tx clones
	edge = rte_node_edge_update(
		port_output_node, 0, (const char **)tx_node_names, gr_vec_len(tx_node_names)
	);
	assert(edge != RTE_EDGE_ID_INVALID);
	edge = rte_node_edge_shrink(port_output_node, gr_vec_len(tx_node_names));
	assert(edge != RTE_EDGE_ID_INVALID);

	// store all unused node_ids in a list to be returned to the caller
	gr_vec_foreach (name, old_rx)
		gr_vec_add(unused_nodes, rte_node_from_name(name));
	gr_vec_foreach (name, old_tx)
		gr_vec_add(unused_nodes, rte_node_from_name(name));
	gr_strvec_free(old_rx);
	gr_strvec_free(old_tx);

	return unused_nodes;
}

int worker_graph_reload_all(gr_vec struct iface_info_port **ports) {
	struct worker *worker;
	int ret;

	gr_vec rte_node_t *unused_nodes = worker_graph_nodes_add_missing(ports);

	STAILQ_FOREACH (worker, &workers, next) {
		if ((ret = worker_graph_reload(worker, ports)) < 0)
			return ret;
	}

	// these port_rx and port_tx clones are now not referenced in any graph
	// we can safely delete them
	// FIXME: call rte_node_free on each one of them when updating to DPDK 25.11
	gr_vec_free(unused_nodes);

	return 0;
}

const struct gr_node_info *gr_node_info_get(rte_node_t node_id) {
	const struct gr_node_info *info;

	STAILQ_FOREACH (info, &node_infos, next)
		if (info->node->id == node_id)
			return info;

	return errno_set_null(ENOENT);
}

static struct api_out graph_dump(const void *request, struct api_ctx *) {
	const struct gr_infra_graph_dump_req *req = request;
	bool errors = req->flags & GR_INFRA_GRAPH_DUMP_F_ERRORS;
	gr_vec const char **seen_edges = NULL;
	struct gr_node_info *info;
	char **edges = NULL;
	size_t buf_len = 0;
	char *buf = NULL;
	FILE *f = NULL;

	if ((f = open_memstream(&buf, &buf_len)) == NULL)
		return api_out(errno, 0, NULL);

	if (fprintf(f, "digraph grout {\n\trankdir=LR;\n") < 0)
		goto err;
	if (fprintf(f, "\tnode [margin=0.02 fontsize=11 fontname=sans];\n") < 0)
		goto err;

	STAILQ_FOREACH (info, &node_infos, next) {
		rte_node_t node_id = rte_node_from_name(info->node->name);
		unsigned nb_edges = rte_node_edge_count(node_id);
		const char *name = info->node->name;
		const char *attrs = "";

		if (node_id == port_output_node)
			nb_edges = info->node->nb_edges;

		if (!errors) {
			if (nb_edges == 0)
				continue;
			if (strstr(name, "error"))
				continue;
		}
		if (fprintf(f, "\t\"%s\"", name) < 0)
			goto err;

		if (info->node->flags & RTE_NODE_SOURCE_F) {
			attrs = " [color=blue style=bold]";
			if (fprintf(f, "%s", attrs) < 0)
				goto err;
		} else if (nb_edges == 0) {
			if (fprintf(f, " [fontcolor=darkorange shape=plain]") < 0)
				goto err;
		}

		if (fprintf(f, ";\n") < 0)
			goto err;

		if (nb_edges == 0)
			continue;
		if ((edges = calloc(nb_edges, sizeof(char *))) == NULL)
			goto err;
		if (node_id == port_output_node) {
			for (unsigned i = 0; i < nb_edges; i++)
				edges[i] = (char *)info->node->next_nodes[i];
		} else if (rte_node_edge_get(node_id, edges) == RTE_EDGE_ID_INVALID)
			goto err;

		for (unsigned i = 0; i < nb_edges; i++) {
			const char *edge = edges[i];
			const char *node_attrs = attrs;

			gr_vec_foreach (const char *e, seen_edges) {
				if (strcmp(e, edge) == 0)
					goto skip; // skip duplicate edges
			}

			const struct gr_node_info *n;
			STAILQ_FOREACH (n, &node_infos, next) {
				if (strcmp(n->node->name, edge) != 0)
					continue;

				rte_node_t id = rte_node_from_name(n->node->name);
				if (id != port_output_node && rte_node_edge_count(id) == 0) {
					if (!errors)
						goto skip;
					node_attrs = " [color=darkorange]";
				}
				break;
			}

			gr_vec_add(seen_edges, edge);

			if (fprintf(f, "\t\"%s\" -> \"%s\"%s;\n", name, edge, node_attrs) < 0)
				goto err;
skip:;
		}
		free(edges);
		edges = NULL;
		gr_vec_free(seen_edges);
	}

	// terminate with nul character
	if (fprintf(f, "}\n%c", '\0') < 0)
		goto err;

	fflush(f);
	fclose(f);

	return api_out(0, buf_len, buf);

err:
	int errsave = errno;
	fclose(f);
	free(buf);
	free(edges);
	gr_vec_free(seen_edges);
	return api_out(errsave, 0, NULL);
}

static struct gr_api_handler graph_dump_handler = {
	.name = "graph dump",
	.request_type = GR_INFRA_GRAPH_DUMP,
	.callback = graph_dump,
};

static void graph_init(struct event_base *) {
	struct rte_node_register *reg;
	struct gr_node_info *info;

	// register nodes first
	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->node == NULL)
			ABORT("info->node == NULL");
		reg = info->node;
		reg->parent_id = RTE_NODE_ID_INVALID;
		reg->id = __rte_node_register(reg);
		if (reg->id == RTE_NODE_ID_INVALID)
			ABORT("__rte_node_register(%s): %s", reg->name, rte_strerror(rte_errno));

		if (strcmp(reg->name, RX_NODE_BASE) == 0)
			port_rx_node = reg->id;
		else if (strcmp(reg->name, TX_NODE_BASE) == 0)
			port_tx_node = reg->id;
		else
			gr_vec_add(base_node_names, reg->name);

		if (strcmp(reg->name, "port_output") == 0)
			port_output_node = reg->id;
	}

	// then, invoke all registration callbacks where applicable
	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->register_callback != NULL) {
			info->register_callback();
		}
	}
}

static void graph_fini(struct event_base *) {
	struct gr_node_info *info;

	STAILQ_FOREACH (info, &node_infos, next) {
		if (info->unregister_callback != NULL) {
			info->unregister_callback();
		}
	}

	gr_vec_free(base_node_names);
	gr_strvec_free(rx_node_names);
	gr_strvec_free(tx_node_names);
}

static struct gr_module graph_module = {
	.name = "graph",
	.depends_on = "iface",
	.init = graph_init,
	.fini = graph_fini,
};

RTE_INIT(control_graph_init) {
	gr_register_api_handler(&graph_dump_handler);
	gr_register_module(&graph_module);
}
