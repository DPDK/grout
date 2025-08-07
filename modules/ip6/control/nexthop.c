// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_clock.h>
#include <gr_icmp6.h>
#include <gr_iface.h>
#include <gr_ip6.h>
#include <gr_ip6_control.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_net_types.h>
#include <gr_queue.h>
#include <gr_vec.h>

#include <event2/event.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip6.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>

enum {
	NH6_SINK = 0,
	NH6_IP6_OUTPUT,
	INVALID_ROUTE,
	ERR_NH_ALLOC,
	ERR_ROUTE_INSERT,
	DROP_QUEUE_FULL,
	NH6_EDGE_COUNT,
};

static uint16_t nh6_unreachable_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	struct rte_mbuf *m;
	struct nexthop *nh;
	rte_edge_t edge;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		struct rte_ipv6_hdr *ip = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
		const struct rte_ipv6_addr *dst = &ip->dst_addr;
		edge = NH6_SINK;

		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		nh = rib6_lookup(mbuf_data(m)->iface->vrf_id, mbuf_data(m)->iface->id, dst);
		if (nh == NULL) {
			edge = INVALID_ROUTE;
			goto next; // route to dst has disappeared
		}
		if (nh->flags & GR_NH_F_LINK && !rte_ipv6_addr_eq(dst, &nh->ipv6)) {
			// The resolved nexthop is associated with a "connected" route.
			// We currently do not have an explicit route entry for this
			// destination IP.
			struct nexthop *remote = nh6_lookup(
				nh->vrf_id, mbuf_data(m)->iface->id, dst
			);

			if (remote == NULL) {
				// No existing nexthop for this IP, create one.
				remote = nexthop_new(&(struct gr_nexthop) {
					.type = GR_NH_T_L3,
					.af = GR_AF_IP6,
					.vrf_id = nh->vrf_id,
					.iface_id = nh->iface_id,
					.ipv6 = *dst,
					.origin = GR_NH_ORIGIN_INTERNAL,
				});
			}

			if (remote == NULL) {
				LOG(ERR, "cannot allocate nexthop: %s", strerror(errno));
				edge = ERR_NH_ALLOC;
				goto next;
			}
			if (remote->iface_id != nh->iface_id)
				ABORT(IP6_F " nexthop lookup gives wrong interface", &ip);

			// Create an associated /128 route so that next packets take it
			// in priority with a single route lookup.
			int ret = rib6_insert(
				nh->vrf_id,
				nh->iface_id,
				dst,
				RTE_IPV6_MAX_DEPTH,
				GR_NH_ORIGIN_INTERNAL,
				remote
			);
			if (ret < 0) {
				LOG(ERR, "failed to insert route: %s", strerror(errno));
				edge = ERR_ROUTE_INSERT;
				goto next;
			}
			nh = remote;
		}

		if (nh->state == GR_NH_S_REACHABLE) {
			// The nexthop may have become reachable while the packet was
			// passed from the datapath to here. Re-send it to datapath.
			struct ip6_output_mbuf_data *d = ip6_output_mbuf_data(m);
			d->nh = nh;
			edge = NH6_IP6_OUTPUT;
			goto next;
		}

		if (nh->held_pkts < nh_conf.max_held_pkts) {
			queue_mbuf_data(m)->next = NULL;
			if (nh->held_pkts_head == NULL)
				nh->held_pkts_head = m;
			else
				queue_mbuf_data(nh->held_pkts_tail)->next = m;
			nh->held_pkts_tail = m;
			nh->held_pkts++;
			if (nh->state != GR_NH_S_PENDING) {
				nh6_solicit(nh);
				nh->state = GR_NH_S_PENDING;
			}
			continue; // Do NOT enqueue the packet, it will be sent later
		} else {
			LOG(DEBUG, IP6_F " hold queue full", &dst);
			edge = DROP_QUEUE_FULL;
		}
next:
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static struct rte_node_register nh6_unreachable_node = {
	.flags = GR_NODE_FLAG_CONTROL_PLANE,
	.name = "nh6_unreachable",
	.process = nh6_unreachable_process,
	.nb_edges = NH6_EDGE_COUNT,
	.next_nodes = {
		[NH6_SINK] = "ctlplane_sink",
		[NH6_IP6_OUTPUT] = "ip6_output",
		[INVALID_ROUTE] = "nh6_invalid_route",
		[ERR_NH_ALLOC] = "nh6_nh_alloc",
		[ERR_ROUTE_INSERT] = "nh6_route_insert",
		[DROP_QUEUE_FULL] = "nh6_queue_full",
	},
};

static struct gr_node_info nh6_unreachable_info = {
	.node = &nh6_unreachable_node,
};

GR_NODE_REGISTER(nh6_unreachable_info);

GR_DROP_REGISTER(nh6_invalid_route);
GR_DROP_REGISTER(nh6_nh_alloc);
GR_DROP_REGISTER(nh6_route_insert);
GR_DROP_REGISTER(nh6_queue_full);

enum {
	SINK = 0,
	NDP_NA_OUTPUT,
	IP6_OUTPUT,
	ERR_ICMP6_OPT_INVAL,
	ERR_ICMP6_TYPE_INVAL,
	ERR_NDP_NH_ALLOC,
	ERR_NDP_ROUTE_INSERT,
	NDP_EDGE_COUNT,
};

static uint16_t ndp_probe_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct rte_ipv6_addr *remote, *local;
	const struct ip6_local_mbuf_data *d;
	const struct icmp6_neigh_solicit *ns;
	const struct icmp6_neigh_advert *na;
	icmp6_opt_found_t lladdr_found;
	const struct icmp6 *icmp6;
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct nexthop *nh;
	rte_edge_t edge;

	struct rte_mbuf *m;
	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		edge = SINK;
		nh = NULL;

		if (gr_mbuf_is_traced(m))
			gr_mbuf_trace_add(m, node, 0);

		icmp6 = rte_pktmbuf_mtod(m, const struct icmp6 *);
		d = ip6_local_mbuf_data(m);
		iface = d->iface;

		switch (icmp6->type) {
		case ICMP6_TYPE_NEIGH_SOLICIT:
			ns = PAYLOAD(icmp6);
			local = &ns->target;
			remote = &d->src;
			lladdr_found = icmp6_get_opt(
				m, sizeof(*icmp6) + sizeof(*ns), ICMP6_OPT_SRC_LLADDR, &mac
			);
			break;
		case ICMP6_TYPE_NEIGH_ADVERT:
			na = PAYLOAD(icmp6);
			local = NULL;
			remote = &na->target;
			lladdr_found = icmp6_get_opt(
				m, sizeof(*icmp6) + sizeof(*na), ICMP6_OPT_TARGET_LLADDR, &mac
			);
			break;
		default:
			edge = ERR_ICMP6_TYPE_INVAL;
			goto next;
		}

		if (lladdr_found == ICMP6_OPT_INVAL) {
			LOG(DEBUG, "invalid ICMP6 option %d", icmp6->type);
			edge = ERR_ICMP6_OPT_INVAL;
			goto next;
		};

		if (!rte_ipv6_addr_is_unspec(remote) && !rte_ipv6_addr_is_mcast(remote)) {
			nh = nh6_lookup(iface->vrf_id, iface->id, remote);
			if (nh == NULL) {
				// We don't have an entry for the probe sender address yet.
				//
				// Create one now. If the sender has requested our mac address, they
				// will certainly contact us soon and it will save us an NDP solicitation.
				nh = nexthop_new(&(struct gr_nexthop) {
					.type = GR_NH_T_L3,
					.af = GR_AF_IP6,
					.vrf_id = iface->vrf_id,
					.iface_id = iface->id,
					.ipv6 = *remote,
					.origin = GR_NH_ORIGIN_INTERNAL,
				});
				if (nh == NULL) {
					LOG(ERR, "ip6_nexthop_new: %s", strerror(errno));
					edge = ERR_NDP_NH_ALLOC;
					goto next;
				}

				// Add an internal /128 route to reference the newly created nexthop.
				int ret = rib6_insert(
					iface->vrf_id,
					iface->id,
					remote,
					RTE_IPV6_MAX_DEPTH,
					GR_NH_ORIGIN_INTERNAL,
					nh
				);
				if (ret < 0) {
					LOG(ERR, "ip6_route_insert: %s", strerror(errno));
					edge = ERR_NDP_ROUTE_INSERT;
					goto next;
				}
			}
		}

		if (nh && !(nh->flags & GR_NH_F_STATIC) && lladdr_found == ICMP6_OPT_FOUND) {
			// Refresh all fields.
			nh->last_reply = gr_clock_us();
			nh->state = GR_NH_S_REACHABLE;
			nh->ucast_probes = 0;
			nh->bcast_probes = 0;
			nh->mac = mac;
		}

		if (icmp6->type == ICMP6_TYPE_NEIGH_SOLICIT && local != NULL) {
			// send a reply for our local ip
			struct ndp_na_output_mbuf_data *d = ndp_na_output_mbuf_data(m);
			d->local = nh6_lookup(iface->vrf_id, iface->id, local);
			d->remote = nh;
			d->iface = iface;
			edge = NDP_NA_OUTPUT;
		}

		// Flush all held packets.
		struct rte_mbuf *held = nh->held_pkts_head;
		while (held != NULL) {
			struct ip6_output_mbuf_data *o;
			struct rte_mbuf *next;

			next = queue_mbuf_data(held)->next;
			o = ip6_output_mbuf_data(held);
			o->nh = nh;
			o->iface = NULL;
			rte_node_enqueue_x1(graph, node, IP6_OUTPUT, held);
			held = next;
		}
		nh->held_pkts_head = NULL;
		nh->held_pkts_tail = NULL;
		nh->held_pkts = 0;
next:
		rte_node_enqueue_x1(graph, node, edge, m);
		continue;
	}
	return nb_objs;
}

static struct rte_node_register ndp_probe_node = {
	.flags = GR_NODE_FLAG_CONTROL_PLANE,
	.name = "ndp_probe",
	.process = ndp_probe_input_process,
	.nb_edges = NDP_EDGE_COUNT,
	.next_nodes = {
		[SINK] = "ctlplane_sink",
		[IP6_OUTPUT] = "ip6_output",
		[NDP_NA_OUTPUT] = "ndp_na_output",
		[ERR_ICMP6_OPT_INVAL] = "ndp_icmp6_opt_inval",
		[ERR_ICMP6_TYPE_INVAL] = "ndp_icmp6_type_inval",
		[ERR_NDP_ROUTE_INSERT] = "ndp_route_insert",
		[ERR_NDP_NH_ALLOC] = "ndp_nh_alloc",
	},
};

static struct gr_node_info ndp_probe_info = {
	.node = &ndp_probe_node,
};

GR_NODE_REGISTER(ndp_probe_info);
GR_DROP_REGISTER(ndp_icmp6_opt_inval);
GR_DROP_REGISTER(ndp_icmp6_type_inval);
GR_DROP_REGISTER(ndp_route_insert);
GR_DROP_REGISTER(ndp_nh_alloc);

static int nh6_add(struct nexthop *nh) {
	return rib6_insert(nh->vrf_id, nh->iface_id, &nh->ipv6, 128, GR_NH_ORIGIN_INTERNAL, nh);
}

static void nh6_del(struct nexthop *nh) {
	rib6_delete(nh->vrf_id, nh->iface_id, &nh->ipv6, RTE_IPV6_MAX_DEPTH, nh->type);
	if (nh->ref_count > 0) {
		nh->state = GR_NH_S_NEW;
		memset(&nh->mac, 0, sizeof(nh->mac));
	}
}

static struct gr_module nh6_module = {
	.name = "ipv6 nexthop",
	.depends_on = "graph",
};

static struct nexthop_af_ops nh_ops = {
	.add = nh6_add,
	.solicit = nh6_solicit,
	.del = nh6_del,
};

RTE_INIT(control_ip_init) {
	gr_register_module(&nh6_module);
	nexthop_af_ops_register(GR_AF_IP6, &nh_ops);
}
