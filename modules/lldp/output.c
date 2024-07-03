// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "gr_lldp.h"
#include "lldp_priv.h"

#include <gr_control_input.h>
#include <gr_eth_input.h>
#include <gr_eth_output.h>
#include <gr_graph.h>
#include <gr_ip4_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_port.h>

#include <rte_ether.h>
#include <rte_graph_worker.h>
#include <rte_malloc.h>
#include <rte_version.h>

enum {
	OUTPUT = 0,
	ERROR,
	EDGE_COUNT,
};

extern struct gr_lldp_conf_common_data lldp_ctx;
extern struct gr_lldp_conf_iface_data lldp_iface_ctx[RTE_MAX_ETHPORTS];

const struct rte_ether_addr lldp_dst = {
	.addr_bytes = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
};

static control_input_t lldp_control_id;

int lldp_output_emit(const struct iface *iface) {
	int ret;
	if (iface == NULL)
		return errno_set(EINVAL);

	ret = post_to_stack(lldp_control_id, (struct iface *)iface);
	if (ret < 0)
		return errno_set(-ret);

	return 0;
}

static uint8_t *lldp_tlv_append(
	struct rte_mbuf *mbuf,
	uint8_t type,
	uint8_t subtype,
	uint16_t value_len,
	void *value
) {
	uint8_t offset = 2;
	uint8_t *data = (uint8_t *)
		rte_pktmbuf_append(mbuf, 2 + value_len + (subtype != T_NO_SUBTYPE ? 1 : 0));
	if (data) {
		uint16_t total_len = value_len;
		if (subtype != T_NO_SUBTYPE) {
			total_len += 1;
			offset += 1;
			data[2] = subtype;
		}
		// First 7 bits sets the type, the 9 following bits for the length
		data[0] = type << 1 | total_len >> 7;
		data[1] = total_len & 0xff;
		memcpy(&data[offset], value, value_len);
	}
	return data;
}

static bool build_lldp_frame(struct rte_mbuf *mbuf, const struct iface *iface) {
	struct lldp_ip4 lldp_ip4 = {.afi = AFI_IP_4};
	struct rte_ether_addr src_addr;
	struct iface_info_port *port;
	struct nexthop *local_ip;
	uint16_t ttl_value;

	port = (struct iface_info_port *)iface->info;
	iface_get_eth_addr(iface->id, &src_addr);

	if (lldp_iface_ctx[port->port_id].tx) {
		ttl_value = rte_cpu_to_be_16(lldp_ctx.ttl);
	} else {
		// Specific case: TX is disabled, but we want to
		// send a last message with a TTL set to 0
		ttl_value = 0;
	}

	// Only T_CHASSIS_ID T_PORT_ID T_TTL and T_END are mandatory
	lldp_tlv_append(
		mbuf, T_CHASSIS_ID, T_CHASSIS_MAC_ADDRESS, RTE_ETHER_ADDR_LEN, src_addr.addr_bytes
	);
	lldp_tlv_append(
		mbuf, T_CHASSIS_ID, T_CHASSIS_IF_ALIAS, strlen(lldp_ctx.sys_name), lldp_ctx.sys_name
	);
	lldp_tlv_append(
		mbuf, T_PORT_ID, T_PORT_MAC_ADDRESS, RTE_ETHER_ADDR_LEN, src_addr.addr_bytes
	);
	lldp_tlv_append(mbuf, T_PORT_ID, T_PORT_IF_ALIAS, strlen(iface->name), iface->name);
	lldp_tlv_append(mbuf, T_TTL, T_NO_SUBTYPE, sizeof(ttl_value), &ttl_value);

	lldp_tlv_append(mbuf, T_PORT_DESC, T_NO_SUBTYPE, strlen(iface->name), iface->name);
	lldp_tlv_append(
		mbuf, T_SYSTEM_NAME, T_NO_SUBTYPE, strlen(lldp_ctx.sys_name), lldp_ctx.sys_name
	);
	lldp_tlv_append(
		mbuf, T_SYSTEM_DESC, T_NO_SUBTYPE, strlen(lldp_ctx.sys_descr), lldp_ctx.sys_descr
	);

	local_ip = ip4_addr_get_preferred(iface->id, 0);
	if (local_ip) {
		lldp_ip4.ip4_addr = local_ip->ip;
		lldp_tlv_append(
			mbuf,
			T_CHASSIS_ID,
			T_CHASSIS_NET_ADDRESS,
			sizeof(struct lldp_ip4),
			&lldp_ip4
		);
	}

	return lldp_tlv_append(mbuf, T_END, T_NO_SUBTYPE, 0, NULL) != NULL;
}

static uint16_t
lldp_output_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t n_objs) {
	struct eth_output_mbuf_data *eth_data;
	const struct iface *iface;
	struct rte_mbuf *m;

	for (unsigned i = 0; i < n_objs; i++) {
		m = objs[i];
		iface = (const struct iface *)control_input_mbuf_data(m)->data;

		if (build_lldp_frame(m, iface) == false) {
			rte_node_enqueue_x1(graph, node, ERROR, m);
			break;
		}

		// Prepare ethernet layer info.
		eth_data = eth_output_mbuf_data(m);
		rte_ether_addr_copy(&lldp_dst, &eth_data->dst);
		eth_data->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP);
		eth_data->iface = iface;

		rte_node_enqueue_x1(graph, node, OUTPUT, m);
	}

	return n_objs;
}

static void lldp_output_register(void) {
	lldp_control_id = gr_control_input_register_handler("lldp_output");
}

static struct rte_node_register lldp_output_node = {
	.name = "lldp_output",
	.process = lldp_output_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {[OUTPUT] = "eth_output", [ERROR] = "lldp_output_error"},
};

static struct gr_node_info info = {
	.node = &lldp_output_node,
	.register_callback = lldp_output_register,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(lldp_output_error);
