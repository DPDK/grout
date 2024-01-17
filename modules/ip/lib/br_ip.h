// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Robin Jarry

#ifndef _BR_IP
#define _BR_IP

#include <br_client.h>
#include <br_ip_types.h>
#include <br_net_types.h>

#include <stdbool.h>
#include <stddef.h>

int br_ip_nh4_add(const struct br_client *, const struct br_ip_nh4 *, bool exist_ok);
int br_ip_nh4_del(const struct br_client *, ip4_addr_t, bool missing_ok);
int br_ip_nh4_list(const struct br_client *, size_t *n_nhs, struct br_ip_nh4 **);

int br_ip_route4_add(const struct br_client *, const struct ip4_net *, ip4_addr_t, bool exist_ok);
int br_ip_route4_del(const struct br_client *, const struct ip4_net *, bool missing_ok);
int br_ip_route4_list(const struct br_client *, size_t *n_routes, struct br_ip_route4 **);

#endif
