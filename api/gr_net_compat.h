// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_NET_COMPAT
#define _GR_NET_COMPAT

#include <limits.h>
#include <stdint.h>

#define RTE_IPV6_ADDR_SIZE 16
#define RTE_IPV6_MAX_DEPTH (RTE_IPV6_ADDR_SIZE * CHAR_BIT)

struct rte_ipv6_addr {
	uint8_t a[RTE_IPV6_ADDR_SIZE];
};

static inline void rte_ipv6_addr_mask(struct rte_ipv6_addr *ip, uint8_t depth) {
	if (depth < RTE_IPV6_MAX_DEPTH) {
		unsigned int d = depth / CHAR_BIT;
		uint8_t mask = ~(UINT8_MAX >> (depth % CHAR_BIT));
		ip->a[d] &= mask;
		d++;
		while (d < sizeof(*ip))
			ip->a[d++] = 0;
	}
}

#define RTE_ETHER_ADDR_LEN 6

struct __attribute__((aligned(2))) rte_ether_addr {
	uint8_t addr_bytes[RTE_ETHER_ADDR_LEN];
};

/* ICMP packet types */
#define RTE_ICMP_TYPE_ECHO_REPLY 0
#define RTE_ICMP_TYPE_DEST_UNREACHABLE 3
#define RTE_ICMP_TYPE_REDIRECT 5
#define RTE_ICMP_TYPE_ECHO_REQUEST 8
#define RTE_ICMP_TYPE_TTL_EXCEEDED 11
#define RTE_ICMP_TYPE_PARAM_PROBLEM 12
#define RTE_ICMP_TYPE_TIMESTAMP_REQUEST 13
#define RTE_ICMP_TYPE_TIMESTAMP_REPLY 14

/* Destination Unreachable codes */
#define RTE_ICMP_CODE_UNREACH_NET 0
#define RTE_ICMP_CODE_UNREACH_HOST 1
#define RTE_ICMP_CODE_UNREACH_PROTO 2
#define RTE_ICMP_CODE_UNREACH_PORT 3
#define RTE_ICMP_CODE_UNREACH_FRAG 4
#define RTE_ICMP_CODE_UNREACH_SRC 5

/* Time Exceeded codes */
#define RTE_ICMP_CODE_TTL_EXCEEDED 0
#define RTE_ICMP_CODE_TTL_FRAG 1

/* Redirect codes */
#define RTE_ICMP_CODE_REDIRECT_NET 0
#define RTE_ICMP_CODE_REDIRECT_HOST 1
#define RTE_ICMP_CODE_REDIRECT_TOS_NET 2
#define RTE_ICMP_CODE_REDIRECT_TOS_HOST 3

#endif
