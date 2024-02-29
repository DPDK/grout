// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_MSG
#define _BR_INFRA_MSG

#include <br_api.h>
#include <br_infra_types.h>

#define BR_INFRA_MODULE 0xacdc

// ports
#define BR_INFRA_PORT_ADD REQUEST_TYPE(BR_INFRA_MODULE, 0x0001)

struct br_infra_port_add_req {
	char devargs[128];
};

struct br_infra_port_add_resp {
	uint16_t port_id;
};

#define BR_INFRA_PORT_DEL REQUEST_TYPE(BR_INFRA_MODULE, 0x0002)

struct br_infra_port_del_req {
	uint16_t port_id;
};

// struct br_infra_port_del_resp { };

#define BR_INFRA_PORT_GET REQUEST_TYPE(BR_INFRA_MODULE, 0x0003)

struct br_infra_port_get_req {
	uint16_t port_id;
};

struct br_infra_port_get_resp {
	struct br_infra_port port;
};

#define BR_INFRA_PORT_LIST REQUEST_TYPE(BR_INFRA_MODULE, 0x0004)

// struct br_infra_port_list_req { };

struct br_infra_port_list_resp {
	uint16_t n_ports;
	struct br_infra_port ports[/* n_ports */];
};

#define BR_INFRA_PORT_SET REQUEST_TYPE(BR_INFRA_MODULE, 0x0005)

typedef enum {
	BR_INFRA_PORT_N_RXQ = BR_BIT32(0),
	BR_INFRA_PORT_BURST = BR_BIT32(1),
} br_infra_port_attr_t;

#define BR_INFRA_PORT_BURST_DEFAULT 32

struct br_infra_port_set_req {
	uint16_t port_id;
	br_infra_port_attr_t set_attrs;
	uint16_t n_rxq;
	uint16_t burst;
};

// struct br_infra_port_set_resp { };

// port rxqs
#define BR_INFRA_RXQ_LIST REQUEST_TYPE(BR_INFRA_MODULE, 0x0010)

// struct br_infra_rxq_list_req { };

struct br_infra_rxq_list_resp {
	uint16_t n_rxqs;
	struct br_infra_rxq rxqs[/* n_rxq */];
};

#define BR_INFRA_RXQ_SET REQUEST_TYPE(BR_INFRA_MODULE, 0x0011)

struct br_infra_rxq_set_req {
	uint16_t port_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
};

// struct br_infra_rxq_set_resp { };

#endif
