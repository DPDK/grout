// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BROUTER_API_PLATFORM
#define _BROUTER_API_PLATFORM

#include <bro_api.h>

#include <rte_build_config.h>

#include <stdint.h>

struct bro_port {
	uint32_t index;
	uint16_t mtu;
	uint8_t mac[6];
	char name[64];
	char description[128];
	char devargs[128];
};

#define BRO_PLATFORM_PORT_ADD 1
struct bro_port_add_req {
	struct bro_port port;
};

// struct bro_port_add_resp { };

#define BRO_PLATFORM_PORT_GET 2
struct bro_port_get_req {
	char name[64];
};

struct bro_port_get_resp {
	struct bro_port port;
};

#define BRO_PLATFORM_PORT_DEL 3
struct bro_port_del_req {
	char name[64];
};

// struct bro_port_del_resp { };

#define BRO_PLATFORM_PORT_LIST 4
// struct bro_port_list_req { };

struct bro_port_list_resp {
	uint8_t num_ports;
	struct bro_port ports[RTE_MAX_ETHPORTS];
};

#endif // _BROUTER_API_PLATFORM
