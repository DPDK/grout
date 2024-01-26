// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP_MSG
#define _BR_IP_MSG

#include <br_api.h>
#include <br_ip_types.h>

#define BR_IP_MODULE 0xf00d

// next hops ///////////////////////////////////////////////////////////////////

#define BR_IP_NH4_ADD REQUEST_TYPE(BR_IP_MODULE, 0x0001)

struct br_ip_nh4_add_req {
	struct br_ip_nh4 nh;
	uint8_t exist_ok;
};

// struct br_ip_nh4_add_resp { };

#define BR_IP_NH4_DEL REQUEST_TYPE(BR_IP_MODULE, 0x0002)

struct br_ip_nh4_del_req {
	ip4_addr_t host;
	uint8_t missing_ok;
};

// struct br_ip_nh4_del_resp { };

#define BR_IP_NH4_LIST REQUEST_TYPE(BR_IP_MODULE, 0x0003)

// struct br_ip_nh4_list_req { };

struct br_ip_nh4_list_resp {
	uint16_t n_nhs;
	struct br_ip_nh4 nhs[/* n_nhs */];
};

// routes //////////////////////////////////////////////////////////////////////

#define BR_IP_ROUTE4_ADD REQUEST_TYPE(BR_IP_MODULE, 0x0010)

struct br_ip_route4_add_req {
	struct ip4_net dest;
	ip4_addr_t nh;
	uint8_t exist_ok;
};

// struct br_ip_route4_add_resp { };

#define BR_IP_ROUTE4_DEL REQUEST_TYPE(BR_IP_MODULE, 0x0011)

struct br_ip_route4_del_req {
	struct ip4_net dest;
	uint8_t missing_ok;
};

// struct br_ip_route4_del_resp { };

#define BR_IP_ROUTE4_GET REQUEST_TYPE(BR_IP_MODULE, 0x0012)

struct br_ip_route4_get_req {
	ip4_addr_t dest;
};

struct br_ip_route4_get_resp {
	struct br_ip_nh4 nh;
};

#define BR_IP_ROUTE4_LIST REQUEST_TYPE(BR_IP_MODULE, 0x0013)

// struct br_ip_route4_list_req { };

struct br_ip_route4_list_resp {
	uint16_t n_routes;
	struct br_ip_route4 routes[/* n_routes */];
};

#endif
