// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP4_MSG
#define _BR_IP4_MSG

#include <br_api.h>
#include <br_ip4_types.h>

#define BR_IP4_MODULE 0xf00d

// next hops ///////////////////////////////////////////////////////////////////

#define BR_IP4_NH_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0001)

struct br_ip4_nh_add_req {
	struct br_ip4_nh nh;
	uint8_t exist_ok;
};

// struct br_ip4_nh_add_resp { };

#define BR_IP4_NH_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0002)

struct br_ip4_nh_del_req {
	ip4_addr_t host;
	uint8_t missing_ok;
};

// struct br_ip4_nh_del_resp { };

#define BR_IP4_NH_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0003)

// struct br_ip4_nh_list_req { };

struct br_ip4_nh_list_resp {
	uint16_t n_nhs;
	struct br_ip4_nh nhs[/* n_nhs */];
};

// routes //////////////////////////////////////////////////////////////////////

#define BR_IP4_ROUTE_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0010)

struct br_ip4_route_add_req {
	struct ip4_net dest;
	ip4_addr_t nh;
	uint8_t exist_ok;
};

// struct br_ip4_route_add_resp { };

#define BR_IP4_ROUTE_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0011)

struct br_ip4_route_del_req {
	struct ip4_net dest;
	uint8_t missing_ok;
};

// struct br_ip4_route_del_resp { };

#define BR_IP4_ROUTE_GET REQUEST_TYPE(BR_IP4_MODULE, 0x0012)

struct br_ip4_route_get_req {
	ip4_addr_t dest;
};

struct br_ip4_route_get_resp {
	struct br_ip4_nh nh;
};

#define BR_IP4_ROUTE_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0013)

// struct br_ip4_route_list_req { };

struct br_ip4_route_list_resp {
	uint16_t n_routes;
	struct br_ip4_route routes[/* n_routes */];
};

// addresses ///////////////////////////////////////////////////////////////////

#define BR_IP4_ADDR_ADD REQUEST_TYPE(BR_IP4_MODULE, 0x0021)

struct br_ip4_addr_add_req {
	struct br_ip4_addr addr;
	uint8_t exist_ok;
};

// struct br_ip4_addr_add_resp { };

#define BR_IP4_ADDR_DEL REQUEST_TYPE(BR_IP4_MODULE, 0x0022)

struct br_ip4_addr_del_req {
	struct br_ip4_addr addr;
	uint8_t missing_ok;
};

// struct br_ip4_addr_del_resp { };

#define BR_IP4_ADDR_LIST REQUEST_TYPE(BR_IP4_MODULE, 0x0023)

// struct br_ip4_addr_list_req { };

struct br_ip4_addr_list_resp {
	uint16_t n_addrs;
	struct br_ip4_addr addrs[/* n_addrs */];
};

#endif
