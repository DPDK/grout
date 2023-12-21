// SPDX-License-Identifier: Apache-2.0
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
} br_infra_port_attr_t;

struct br_infra_port_set_req {
	uint16_t port_id;
	br_infra_port_attr_t set_attrs;
	uint16_t n_rxq;
};

// struct br_infra_port_set_resp { };

// workers
#define BR_INFRA_WORKER_ADD REQUEST_TYPE(BR_INFRA_MODULE, 0x0010)

struct br_infra_worker_add_req {
	uint16_t cpu_id;
};

struct br_infra_worker_add_resp {
	struct br_infra_worker worker;
};

#define BR_INFRA_WORKER_DEL REQUEST_TYPE(BR_INFRA_MODULE, 0x0011)

struct br_infra_worker_del_req {
	uint64_t worker_id;
};

// struct br_infra_worker_del_resp { };

#define BR_INFRA_WORKER_GET REQUEST_TYPE(BR_INFRA_MODULE, 0x0012)

struct br_infra_worker_get_req {
	uint64_t worker_id;
};

struct br_infra_worker_get_resp {
	struct br_infra_worker worker;
};

#define BR_INFRA_WORKER_LIST REQUEST_TYPE(BR_INFRA_MODULE, 0x0013)

// struct br_infra_worker_list_req { };

struct br_infra_worker_list_resp {
	uint16_t n_workers;
	struct br_infra_worker workers[/* n_workers */];
};

#define BR_INFRA_WORKER_SET REQUEST_TYPE(BR_INFRA_MODULE, 0x0014)

struct br_infra_worker_set_req {
	uint64_t worker_id;
	br_infra_worker_attr_t set_attrs;
	uint16_t cpu_id;
	uint8_t n_rx_queues;
	struct br_infra_rxq rx_queues[/* n_rx_queues */];
};

// struct br_infra_worker_set_resp { };

#endif
