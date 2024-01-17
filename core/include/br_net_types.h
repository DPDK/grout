
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_NET_TYPES
#define _BR_NET_TYPES

#include <stdint.h>
#include <stdio.h>

#define ETH_ADDR_RE "^[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}$"
#define ETH_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETH_ADDR_SCAN "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx"
#define ETH_BYTES_SPLIT(b) b[0], b[1], b[2], b[3], b[4], b[5]

struct eth_addr {
	uint8_t bytes[6];
};

static inline int br_eth_addr_scan(const char *str, struct eth_addr *mac) {
	int ret = sscanf(
		str,
		ETH_ADDR_SCAN,
		&mac->bytes[0],
		&mac->bytes[1],
		&mac->bytes[2],
		&mac->bytes[3],
		&mac->bytes[4],
		&mac->bytes[5]
	);
	return ret == 6 ? 0 : -1;
}

#endif
