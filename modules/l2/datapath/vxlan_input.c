// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include "l2_datapath.h"

#include <gr_datapath.h>
#include <gr_eth.h>
#include <gr_graph.h>
#include <gr_ip4_datapath.h>
#include <gr_l2_control.h>
#include <gr_l4.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

enum {
	IFACE_INPUT = 0,
	NO_TUNNEL,
	BAD_FLAGS,
	EDGE_COUNT,
};

int trace_vxlan_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct trace_vxlan_data *t = data;
	int n = snprintf(buf, len, "vni=%u", rte_be_to_cpu_32(t->vni));
	if (t->vtep != 0)
		n += snprintf(buf + n, len - n, " vtep=" IP4_F, &t->vtep);
	return n;
}

static uint16_t
vxlan_input_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs) {
	uint16_t last_vrf_id, vrf_id;
	struct ip_local_mbuf_data *l;
	struct iface_mbuf_data *d;
	struct rte_vxlan_hdr *vh;
	rte_be32_t vni, last_vni;
	ip4_addr_t src_vtep;
	struct iface *iface;
	struct rte_mbuf *m;
	rte_edge_t edge;

	last_vrf_id = GR_VRF_ID_UNDEF;
	last_vni = 0;
	iface = NULL;
	vni = 0;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		l = ip_local_mbuf_data(m);
		vrf_id = l->vrf_id;
		src_vtep = l->src;

		vh = rte_pktmbuf_mtod_offset(m, struct rte_vxlan_hdr *, sizeof(struct rte_udp_hdr));
		if (!(vh->vx_flags & VXLAN_FLAGS_VNI)) {
			edge = BAD_FLAGS;
			goto next;
		}

		vni = vxlan_decode_vni(vh->vx_vni);
		if (vni != last_vni || vrf_id != last_vrf_id) {
			iface = vxlan_get_iface(vni, vrf_id);
			last_vrf_id = vrf_id;
			last_vni = vni;
		}
		if (iface == NULL) {
			edge = NO_TUNNEL;
			goto next;
		}

		rte_pktmbuf_adj(m, sizeof(struct rte_udp_hdr) + sizeof(*vh));

		d = iface_mbuf_data(m);
		d->iface = iface;
		d->vlan_id = 0;
		d->vtep = src_vtep;
		edge = IFACE_INPUT;
next:
		if (gr_mbuf_is_traced(m) || (iface && iface->flags & GR_IFACE_F_PACKET_TRACE)) {
			struct trace_vxlan_data *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->vni = vni;
			t->vtep = src_vtep;
		}
		rte_node_enqueue_x1(graph, node, edge, m);
	}

	return nb_objs;
}

static void vxlan_input_register(void) {
	l4_input_register_port(IPPROTO_UDP, RTE_BE16(RTE_VXLAN_DEFAULT_PORT), "vxlan_input");
}

static struct rte_node_register vxlan_input_node = {
	.name = "vxlan_input",

	.process = vxlan_input_process,

	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[IFACE_INPUT] = "iface_input",
		[NO_TUNNEL] = "vxlan_input_no_tunnel",
		[BAD_FLAGS] = "vxlan_input_bad_flags",
	},
};

static struct gr_node_info vxlan_input_info = {
	.node = &vxlan_input_node,
	.type = GR_NODE_T_L3,
	.register_callback = vxlan_input_register,
	.trace_format = trace_vxlan_format,
};

GR_NODE_REGISTER(vxlan_input_info);

GR_DROP_REGISTER(vxlan_input_no_tunnel);
GR_DROP_REGISTER(vxlan_input_bad_flags);
