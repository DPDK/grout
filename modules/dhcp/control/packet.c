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
	dhcp_message_type_t *msg_type
) {
	struct dhcp_packet *dhcp;
	uint16_t options_len;

	if (rte_pktmbuf_data_len(mbuf) < sizeof(struct rte_udp_hdr) + sizeof(*dhcp))
		return errno_set(ENOBUFS);

	dhcp = rte_pktmbuf_mtod_offset(mbuf, struct dhcp_packet *, sizeof(struct rte_udp_hdr));
	if (dhcp->magic != DHCP_MAGIC)
		return errno_set(EBADMSG);

	if (dhcp->xid != rte_cpu_to_be_32(client->xid)) {
		LOG(DEBUG,
		    "transaction ID mismatch (got 0x%x, expected 0x%x)",
		    rte_be_to_cpu_32(dhcp->xid),
		    client->xid);
		return errno_set(EIDRM);
	}
	if (dhcp->op != BOOTREPLY) {
		LOG(DEBUG, "not a BOOTREPLY");
		return errno_set(EOPNOTSUPP);
	}

	options_len = rte_pktmbuf_data_len(mbuf) - sizeof(struct rte_udp_hdr) - sizeof(*dhcp);
	if (dhcp_parse_options(dhcp->options, options_len, client, msg_type) < 0)
		return -errno;

	client->offered_ip = dhcp->yiaddr;

	LOG(INFO,
	    "received %s from server (xid=0x%08x, offered_ip=" IP4_F ")",
	    dhcp_message_type_name(*msg_type),
	    client->xid,
	    &client->offered_ip);

	return 0;
}

static struct rte_mbuf *dhcp_build_packet(
	uint16_t iface_id,
	uint32_t xid,
	dhcp_message_type_t msg_type,
	ip4_addr_t server_ip,
	ip4_addr_t requested_ip
) {
	static const struct rte_ether_addr broadcast_mac = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
	struct eth_output_mbuf_data *data;
	const struct iface *iface;
	struct rte_ether_addr mac;
	struct dhcp_packet *dhcp;
	struct rte_ipv4_hdr *ip;
	struct rte_udp_hdr *udp;
	struct rte_mbuf *m;
	uint8_t *options;
	int opt_len;

	iface = iface_from_id(iface_id);
	if (iface == NULL)
		return NULL;

	if (iface_get_eth_addr(iface, &mac) < 0)
		return errno_set_null(EMEDIUMTYPE);

	m = rte_pktmbuf_alloc(dhcp_get_mempool());
	if (m == NULL)
		return errno_set_null(ENOMEM);

	data = eth_output_mbuf_data(m);
	data->iface = iface;
	data->dst = broadcast_mac;
	data->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);

	ip = (struct rte_ipv4_hdr *)rte_pktmbuf_append(m, sizeof(*ip));
	if (ip == NULL) {
		errno = ENOBUFS;
		goto err;
	}
	udp = (struct rte_udp_hdr *)rte_pktmbuf_append(m, sizeof(*udp));
	if (udp == NULL) {
		errno = ENOBUFS;
		goto err;
	}
	dhcp = (struct dhcp_packet *)rte_pktmbuf_append(m, sizeof(*dhcp));
	if (dhcp == NULL) {
		errno = ENOBUFS;
		goto err;
	}

	memset(dhcp, 0, sizeof(*dhcp));
	dhcp->op = BOOTREQUEST;
	dhcp->htype = 1;
	dhcp->hlen = 6;
	dhcp->xid = rte_cpu_to_be_32(xid);
	dhcp->flags = RTE_BE16(0x8000); // Broadcast flag
	rte_ether_addr_copy(&mac, (struct rte_ether_addr *)dhcp->chaddr);
	dhcp->magic = DHCP_MAGIC;

	// Allocate space for options (worst case: 22 bytes, see dhcp_build_options)
	options = (uint8_t *)rte_pktmbuf_append(m, 22);
	if (options == NULL) {
		errno = ENOBUFS;
		goto err;
	}

	opt_len = dhcp_build_options(options, 22, msg_type, server_ip, requested_ip);
	if (opt_len < 0) {
		errno = -opt_len;
		goto err;
	}
	rte_pktmbuf_trim(m, 22 - opt_len);

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

err:
	rte_pktmbuf_free(m);
	return NULL;
}

struct rte_mbuf *dhcp_build_discover(uint16_t iface_id, uint32_t xid) {
	return dhcp_build_packet(iface_id, xid, DHCP_DISCOVER, 0, 0);
}

struct rte_mbuf *
dhcp_build_request(uint16_t iface_id, uint32_t xid, ip4_addr_t server_ip, ip4_addr_t requested_ip) {
	return dhcp_build_packet(iface_id, xid, DHCP_REQUEST, server_ip, requested_ip);
}
