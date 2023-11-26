// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_TYPES
#define _BR_INFRA_TYPES

#include <stdint.h>

struct br_ether_addr {
	uint8_t bytes[6];
};

struct br_infra_port {
	uint16_t index;
	char name[64];
	char device[128];
	uint16_t mtu;
	struct br_ether_addr mac;
};

#endif
