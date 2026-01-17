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
			return -1;
		}
		len = options[pos++];

		if (pos + len > options_len) {
			LOG(ERR, "option %u length %u exceeds packet", opt, len);
			return -1;
		}

		switch (opt) {
		case DHCP_OPT_MESSAGE_TYPE:
			if (len != 1) {
				LOG(ERR, "invalid message type length %u", len);
				return -1;
			}
			*msg_type = options[pos];
			break;

		case DHCP_OPT_SUBNET_MASK:
			if (len != 4) {
				LOG(ERR, "invalid subnet mask length %u", len);
				break;
			}
			memcpy(&client->subnet_mask, &options[pos], 4);
			break;

		case DHCP_OPT_ROUTER:
			if (len < 4) {
				LOG(ERR, "invalid router length %u", len);
				break;
			}
			memcpy(&client->router_ip, &options[pos], 4);
			break;

		case DHCP_OPT_SERVER_ID:
			if (len != 4) {
				LOG(ERR, "invalid server ID length %u", len);
				break;
			}
			memcpy(&client->server_ip, &options[pos], 4);
			break;

		case DHCP_OPT_LEASE_TIME:
			if (len != 4) {
				LOG(ERR, "invalid lease time length %u", len);
				break;
			}
			client->lease_time = (options[pos] << 24) | (options[pos + 1] << 16)
				| (options[pos + 2] << 8) | options[pos + 3];
			break;

		case DHCP_OPT_RENEWAL_TIME:
			if (len != 4) {
				LOG(ERR, "invalid renewal time length %u", len);
				break;
			}
			client->renewal_time = (options[pos] << 24) | (options[pos + 1] << 16)
				| (options[pos + 2] << 8) | options[pos + 3];
			break;

		case DHCP_OPT_REBIND_TIME:
			if (len != 4) {
				LOG(ERR, "invalid rebind time length %u", len);
				break;
			}
			client->rebind_time = (options[pos] << 24) | (options[pos + 1] << 16)
				| (options[pos + 2] << 8) | options[pos + 3];
			break;

		default:
			LOG(DEBUG, "ignoring option %u (len=%u)", opt, len);
			break;
		}

		pos += len;
	}

	if (*msg_type == 0) {
		LOG(ERR, "no message type found");
		return -1;
	}

	return 0;
}

int dhcp_build_options(uint8_t *buf, uint16_t buf_len, dhcp_message_type_t msg_type) {
	return dhcp_build_options_ex(buf, buf_len, msg_type, 0, 0);
}

int dhcp_build_options_ex(
	uint8_t *buf,
	uint16_t buf_len,
	dhcp_message_type_t msg_type,
	ip4_addr_t server_ip,
	ip4_addr_t requested_ip
) {
	uint16_t pos = 0;

	// Worst case: 3 (msg type) + 6 (server id) + 6 (requested ip) + 6 (param req) + 1 (end) = 22
	if (buf_len < 22) {
		LOG(ERR, "dhcp_build_options: buffer too small");
		return -1;
	}

	// Option 53: DHCP Message Type
	buf[pos++] = DHCP_OPT_MESSAGE_TYPE;
	buf[pos++] = 1; // Length
	buf[pos++] = msg_type;

	// Option 54: Server Identifier
	if (msg_type == DHCP_REQUEST && server_ip != 0) {
		buf[pos++] = DHCP_OPT_SERVER_ID;
		buf[pos++] = 4; // Length
		memcpy(&buf[pos], &server_ip, 4);
		pos += 4;
	}

	// Option 50: Requested IP Address
	if (msg_type == DHCP_REQUEST && requested_ip != 0) {
		buf[pos++] = DHCP_OPT_REQUESTED_IP;
		buf[pos++] = 4; // Length
		memcpy(&buf[pos], &requested_ip, 4);
		pos += 4;
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
