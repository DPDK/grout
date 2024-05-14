// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Robin Jarry

#ifndef _BR_INFRA_MSG
#define _BR_INFRA_MSG

#include <br_api.h>
#include <br_bitops.h>
#include <br_net_types.h>

#include <sched.h>
#include <stdint.h>
#include <sys/types.h>

struct br_infra_port {
	uint16_t index;
	char device[128];
	uint16_t n_rxq;
	uint16_t n_txq;
	uint16_t rxq_size;
	uint16_t txq_size;
	struct eth_addr mac;
};

struct br_infra_rxq {
	uint16_t port_id;
	uint16_t rxq_id;
	uint16_t cpu_id;
	uint16_t enabled;
};

struct br_infra_stat {
	char name[64];
	uint64_t objs;
	uint64_t calls;
	uint64_t cycles;
};

#define BR_INFRA_MODULE 0xacdc

// ports ///////////////////////////////////////////////////////////////////////
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

#define BR_INFRA_PORT_N_RXQ BR_BIT16(0)
#define BR_INFRA_PORT_Q_SIZE BR_BIT16(1)
typedef uint16_t br_infra_port_attr_t;

struct br_infra_port_set_req {
	uint16_t port_id;
	br_infra_port_attr_t set_attrs;
	uint16_t n_rxq;
	uint16_t q_size;
};

// struct br_infra_port_set_resp { };

// port rxqs ///////////////////////////////////////////////////////////////////
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

// stats ///////////////////////////////////////////////////////////////////////
#define BR_INFRA_STAT_F_SW BR_BIT16(0) //!< include software stats
#define BR_INFRA_STAT_F_HW BR_BIT16(1) //!< include hardware stats
#define BR_INFRA_STAT_F_ZERO BR_BIT16(2) //!< include zero value stats
typedef uint16_t br_infra_stats_flags_t;

#define BR_INFRA_STATS_GET REQUEST_TYPE(BR_INFRA_MODULE, 0x0020)

struct br_infra_stats_get_req {
	br_infra_stats_flags_t flags;
	char pattern[64]; // optional glob pattern
};

struct br_infra_stats_get_resp {
	uint16_t n_stats;
	struct br_infra_stat stats[/* n_stats */];
};

#define BR_INFRA_STATS_RESET REQUEST_TYPE(BR_INFRA_MODULE, 0x0021)

// struct br_infra_stats_reset_req { };
// struct br_infra_stats_reset_resp { };

// graph ///////////////////////////////////////////////////////////////////////
#define BR_INFRA_GRAPH_DUMP REQUEST_TYPE(BR_INFRA_MODULE, 0x0030)

// struct br_infra_graph_dump_req { };

struct br_infra_graph_dump_resp {
	uint32_t len;
	char dot[/* len */];
};

#endif
