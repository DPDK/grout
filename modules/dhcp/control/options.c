// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Anthony Harivel

#include "client.h"

#include <gr_log.h>

int dhcp_parse_options(
	const uint8_t *options,
	uint16_t options_len,
	struct dhcp_client *client,
	dhcp_message_type_t *msg_type
) {
	dhcp_option_code_t opt;
	uint16_t pos = 0;
	rte_be32_t time;
	ip4_addr_t mask;
	uint8_t len;

	*msg_type = 0;

	while (pos < options_len) {
		opt = options[pos++];

		if (opt == DHCP_OPT_END)
			break;

		if (opt == DHCP_OPT_PAD)
			continue;

		if (pos >= options_len) {
			LOG(ERR, "truncated option %u", opt);
			return errno_set(EBADMSG);
		}

		len = options[pos++];

		if (pos + len > options_len) {
			LOG(ERR, "option %u length %u exceeds packet", opt, len);
			return errno_set(E2BIG);
		}

		switch (opt) {
		case DHCP_OPT_MESSAGE_TYPE:
			if (len != sizeof(*msg_type)) {
				LOG(ERR, "invalid message type length %u", len);
				return errno_set(EBADMSG);
			}
			*msg_type = options[pos];
			break;

		case DHCP_OPT_SUBNET_MASK:
			if (len != sizeof(mask)) {
				LOG(ERR, "invalid subnet mask length %u", len);
				break;
			}
			memcpy(&mask, &options[pos], 4);
			client->prefixlen = __builtin_popcount(rte_be_to_cpu_32(mask));
			break;

		case DHCP_OPT_ROUTER:
			if (len < sizeof(client->router_ip)) {
				LOG(ERR, "invalid router length %u", len);
				break;
			}
			memcpy(&client->router_ip, &options[pos], sizeof(client->router_ip));
			break;

		case DHCP_OPT_SERVER_ID:
			if (len != sizeof(client->server_ip)) {
				LOG(ERR, "invalid server ID length %u", len);
				break;
			}
			memcpy(&client->server_ip, &options[pos], sizeof(client->server_ip));
			break;

		case DHCP_OPT_LEASE_TIME:
			if (len != sizeof(time)) {
				LOG(ERR, "invalid lease time length %u", len);
				break;
			}
			memcpy(&time, &options[pos], sizeof(time));
			client->lease_time = rte_be_to_cpu_32(time);
			break;

		case DHCP_OPT_RENEWAL_TIME:
			if (len != sizeof(time)) {
				LOG(ERR, "invalid renewal time length %u", len);
				break;
			}
			memcpy(&time, &options[pos], sizeof(time));
			client->renewal_time = rte_be_to_cpu_32(time);
			break;

		case DHCP_OPT_REBIND_TIME:
			if (len != sizeof(time)) {
				LOG(ERR, "invalid rebind time length %u", len);
				break;
			}
			memcpy(&time, &options[pos], sizeof(time));
			client->rebind_time = rte_be_to_cpu_32(time);
			break;

		default:
			LOG(DEBUG, "ignoring option %u (len=%u)", opt, len);
			break;
		}

		pos += len;
	}

	if (*msg_type == 0) {
		LOG(ERR, "no message type found");
		return errno_set(EBADMSG);
	}

	return 0;
}

int dhcp_build_options(
	uint8_t *buf,
	uint16_t buf_len,
	dhcp_message_type_t msg_type,
	ip4_addr_t server_ip,
	ip4_addr_t requested_ip
) {
	uint16_t pos = 0;

	// Worst case: 3 (msg type) + 6 (server id) + 6 (requested ip) + 6 (param req) + 1 (end) = 22
	if (buf_len < 22)
		return errno_set(ENOBUFS);

	// Option 53: DHCP Message Type
	buf[pos++] = DHCP_OPT_MESSAGE_TYPE;
	buf[pos++] = sizeof(msg_type); // Length
	buf[pos++] = msg_type;

	// Option 54: Server Identifier
	if (msg_type == DHCP_REQUEST && server_ip != 0) {
		buf[pos++] = DHCP_OPT_SERVER_ID;
		buf[pos++] = sizeof(server_ip); // Length
		memcpy(&buf[pos], &server_ip, sizeof(server_ip));
		pos += sizeof(server_ip);
	}

	// Option 50: Requested IP Address
	if (msg_type == DHCP_REQUEST && requested_ip != 0) {
		buf[pos++] = DHCP_OPT_REQUESTED_IP;
		buf[pos++] = sizeof(requested_ip); // Length
		memcpy(&buf[pos], &requested_ip, sizeof(requested_ip));
		pos += sizeof(requested_ip);
	}

	// Option 55: Parameter Request List
	buf[pos++] = DHCP_OPT_PARAM_REQUEST_LIST;
	buf[pos++] = 4;
	buf[pos++] = DHCP_OPT_SUBNET_MASK; // 1
	buf[pos++] = DHCP_OPT_ROUTER; // 3
	buf[pos++] = DHCP_OPT_DNS_SERVER; // 6
	buf[pos++] = DHCP_OPT_DOMAIN_NAME; // 15

	// Option 255: End
	buf[pos++] = DHCP_OPT_END;

	return pos;
}
