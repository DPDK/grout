// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include "client.h"

#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_ip4.h>
#include <gr_ip4_control.h>
#include <gr_ip4_datapath.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_net_types.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include <string.h>

int dhcp_parse_packet(
	struct rte_mbuf *mbuf,
	struct dhcp_client *client,
	dhcp_message_type_t *msg_type_out
) {
	dhcp_message_type_t msg_type;
	struct dhcp_packet *dhcp;
	struct rte_udp_hdr *udp;
	uint16_t options_len;
	uint8_t *pkt_data;
	uint16_t pkt_len;
	uint8_t *options;

	pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	pkt_len = rte_pktmbuf_data_len(mbuf);

	if (pkt_len < sizeof(*udp)) {
		LOG(ERR, "dhcp_parse_packet: packet too short for UDP header");
		return -1;
	}
	udp = (struct rte_udp_hdr *)pkt_data;

	if (pkt_len < sizeof(*udp) + sizeof(*dhcp)) {
		LOG(ERR, "dhcp_parse_packet: packet too short for DHCP header");
		return -1;
	}
	dhcp = (struct dhcp_packet *)(pkt_data + sizeof(*udp));

	if (dhcp->magic != DHCP_MAGIC) {
		LOG(ERR, "dhcp_parse_packet: invalid DHCP magic cookie");
		return -1;
	}

	if (dhcp->xid != rte_cpu_to_be_32(client->xid)) {
		LOG(DEBUG,
		    "dhcp_parse_packet: transaction ID mismatch (got 0x%x, expected 0x%x)",
		    rte_be_to_cpu_32(dhcp->xid),
		    client->xid);
		return -1;
	}

	if (dhcp->op != BOOTREPLY) {
		LOG(ERR, "dhcp_parse_packet: not a BOOTREPLY");
		return -1;
	}

	options = dhcp->options;
	options_len = pkt_len - sizeof(*udp) - sizeof(*dhcp);

	if (dhcp_parse_options(options, options_len, client, &msg_type) < 0) {
		LOG(ERR, "dhcp_parse_packet: failed to parse options");
		return -1;
	}

	client->offered_ip = dhcp->yiaddr;

	LOG(INFO,
	    "dhcp: received %s from server (xid=0x%08x, offered_ip=" IP4_F ")",
	    msg_type == DHCP_OFFER	 ? "OFFER" :
		    msg_type == DHCP_ACK ? "ACK" :
					   "other",
	    client->xid,
	    &client->offered_ip);

	if (msg_type_out != NULL)
		*msg_type_out = msg_type;

	return 0;
}

static struct rte_mbuf *dhcp_build_packet_common(
	uint16_t iface_id,
	uint32_t xid,
	dhcp_message_type_t msg_type,
	ip4_addr_t server_ip,
	ip4_addr_t requested_ip,
	const char *caller
) {
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct dhcp_packet *dhcp;
	struct rte_ipv4_hdr *ip;
	struct rte_udp_hdr *udp;
	struct rte_mbuf *m;
	uint8_t *options;
	int opt_len;

	iface = iface_from_id(iface_id);
	if (iface == NULL) {
		LOG(ERR, "%s: interface %u not found", caller, iface_id);
		return NULL;
	}

	if (iface_get_eth_addr(iface, &mac) < 0) {
		LOG(ERR, "%s: failed to get MAC for iface %u", caller, iface_id);
		return NULL;
	}

	m = rte_pktmbuf_alloc(dhcp_get_mempool());
	if (m == NULL) {
		LOG(ERR, "%s: failed to allocate mbuf", caller);
		return NULL;
	}

	mbuf_data(m)->iface = iface;

	struct rte_ether_addr broadcast_mac;
	memset(&broadcast_mac, 0xFF, RTE_ETHER_ADDR_LEN);
	eth_output_mbuf_data(m)->dst = broadcast_mac;
	eth_output_mbuf_data(m)->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);

	ip = (struct rte_ipv4_hdr *)rte_pktmbuf_append(m, sizeof(*ip));
	if (ip == NULL) {
		LOG(ERR, "%s: failed to append IP header", caller);
		rte_pktmbuf_free(m);
		return NULL;
	}

	udp = (struct rte_udp_hdr *)rte_pktmbuf_append(m, sizeof(*udp));
	if (udp == NULL) {
		LOG(ERR, "%s: failed to append UDP header", caller);
		rte_pktmbuf_free(m);
		return NULL;
	}

	dhcp = (struct dhcp_packet *)rte_pktmbuf_append(m, sizeof(*dhcp));
	if (dhcp == NULL) {
		LOG(ERR, "%s: failed to append DHCP packet", caller);
		rte_pktmbuf_free(m);
		return NULL;
	}

	memset(dhcp, 0, sizeof(*dhcp));
	dhcp->op = BOOTREQUEST;
	dhcp->htype = 1;
	dhcp->hlen = 6;
	dhcp->xid = rte_cpu_to_be_32(xid);
	dhcp->flags = RTE_BE16(0x8000); // Broadcast flag
	rte_ether_addr_copy(&mac, (struct rte_ether_addr *)dhcp->chaddr);
	dhcp->magic = DHCP_MAGIC;

	// Allocate space for options (worst case: 22 bytes, see dhcp_build_options_ex)
	options = (uint8_t *)rte_pktmbuf_append(m, 22);
	if (options == NULL) {
		LOG(ERR, "%s: failed to append options", caller);
		rte_pktmbuf_free(m);
		return NULL;
	}

	opt_len = dhcp_build_options_ex(options, 22, msg_type, server_ip, requested_ip);
	if (opt_len < 0) {
		LOG(ERR, "%s: failed to build options", caller);
		rte_pktmbuf_free(m);
		return NULL;
	}

	udp->src_port = RTE_BE16(68);
	udp->dst_port = RTE_BE16(67);
	udp->dgram_len = rte_cpu_to_be_16(sizeof(*udp) + sizeof(*dhcp) + opt_len);
	udp->dgram_cksum = 0;

	ip->version_ihl = RTE_IPV4_VHL_DEF;
	ip->type_of_service = 0;
	ip->total_length = rte_cpu_to_be_16(sizeof(*ip) + sizeof(*udp) + sizeof(*dhcp) + opt_len);
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = 0;
	ip->dst_addr = RTE_BE32(0xFFFFFFFF);
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	return m;
}

struct rte_mbuf *dhcp_build_discover(uint16_t iface_id, uint32_t xid) {
	return dhcp_build_packet_common(iface_id, xid, DHCP_DISCOVER, 0, 0, "dhcp_build_discover");
}

struct rte_mbuf *
dhcp_build_request(uint16_t iface_id, uint32_t xid, ip4_addr_t server_ip, ip4_addr_t requested_ip) {
	return dhcp_build_packet_common(
		iface_id, xid, DHCP_REQUEST, server_ip, requested_ip, "dhcp_build_request"
	);
}
