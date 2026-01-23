// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#pragma once

#include <gr_control_input.h>
#include <gr_control_queue.h>
#include <gr_dhcp.h>

#include <rte_byteorder.h>

#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

struct event;

// DHCP message types (RFC 2132 option 53)
typedef enum : uint8_t {
	DHCP_DISCOVER = 1,
	DHCP_OFFER = 2,
	DHCP_REQUEST = 3,
	DHCP_DECLINE = 4,
	DHCP_ACK = 5,
	DHCP_NAK = 6,
	DHCP_RELEASE = 7,
	DHCP_INFORM = 8,
} dhcp_message_type_t;

static inline const char *dhcp_message_type_name(dhcp_message_type_t type) {
	switch (type) {
	case DHCP_DISCOVER:
		return "DISCOVER";
	case DHCP_OFFER:
		return "OFFER";
	case DHCP_REQUEST:
		return "REQUEST";
	case DHCP_DECLINE:
		return "DECLINE";
	case DHCP_ACK:
		return "ACK";
	case DHCP_NAK:
		return "NAK";
	case DHCP_RELEASE:
		return "RELEASE";
	case DHCP_INFORM:
		return "INFORM";
	}
	return "?";
}

// DHCP options (RFC 2132)
typedef enum : uint8_t {
	DHCP_OPT_PAD = 0,
	DHCP_OPT_SUBNET_MASK = 1,
	DHCP_OPT_ROUTER = 3,
	DHCP_OPT_DNS_SERVER = 6,
	DHCP_OPT_HOSTNAME = 12,
	DHCP_OPT_DOMAIN_NAME = 15,
	DHCP_OPT_REQUESTED_IP = 50,
	DHCP_OPT_LEASE_TIME = 51,
	DHCP_OPT_MESSAGE_TYPE = 53,
	DHCP_OPT_SERVER_ID = 54,
	DHCP_OPT_PARAM_REQUEST_LIST = 55,
	DHCP_OPT_RENEWAL_TIME = 58,
	DHCP_OPT_REBIND_TIME = 59,
	DHCP_OPT_END = 255,
} dhcp_option_code_t;

struct dhcp_client {
	uint16_t iface_id;
	dhcp_state_t state;
	uint32_t xid;
	ip4_addr_t server_ip;
	ip4_addr_t offered_ip;
	ip4_addr_t router_ip;
	uint8_t prefixlen;
	uint32_t lease_time;
	uint32_t renewal_time; // T1 time in seconds
	uint32_t rebind_time; // T2 time in seconds
	time_t lease_start;
	struct event *t1_timer;
	struct event *t2_timer;
	struct event *expire_timer;
};

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	rte_be32_t xid;
	rte_be16_t secs;
	rte_be16_t flags;
	rte_be32_t ciaddr;
	rte_be32_t yiaddr;
	rte_be32_t siaddr;
	rte_be32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	rte_be32_t magic;
	uint8_t options[];
} __attribute__((packed));

#define DHCP_MAGIC RTE_BE32(0x63825363) // RFC 2131 section 3
#define BOOTREQUEST 1
#define BOOTREPLY 2

bool dhcp_enabled(uint16_t iface_id);

void dhcp_input_cb(void *obj, uintptr_t priv, const struct control_queue_drain *);

struct rte_mempool *dhcp_get_mempool(void);

int dhcp_parse_packet(struct rte_mbuf *, struct dhcp_client *, dhcp_message_type_t *);
struct rte_mbuf *dhcp_build_discover(uint16_t iface_id, uint32_t xid);
struct rte_mbuf *
dhcp_build_request(uint16_t iface_id, uint32_t xid, ip4_addr_t server_ip, ip4_addr_t requested_ip);

int dhcp_parse_options(
	const uint8_t *options,
	uint16_t options_len,
	struct dhcp_client *,
	dhcp_message_type_t *
);
int dhcp_build_options(
	uint8_t *buf,
	uint16_t len,
	dhcp_message_type_t,
	ip4_addr_t server_ip,
	ip4_addr_t requested_ip
);
