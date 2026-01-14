// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#pragma once

#include <gr_errno.h>

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __GROUT_MAIN__
#include <rte_ether.h>
#include <rte_ip6.h>
#else
#include <gr_net_compat.h>
#endif

// Address family enumeration.
typedef enum : uint8_t {
	GR_AF_UNSPEC = AF_UNSPEC,
	GR_AF_IP4 = AF_INET,
	GR_AF_IP6 = AF_INET6,
} addr_family_t;

// Convert address family enum to string representation.
static inline const char *gr_af_name(addr_family_t af) {
	switch (af) {
	case GR_AF_UNSPEC:
		return "unspec";
	case GR_AF_IP4:
		return "IPv4";
	case GR_AF_IP6:
		return "IPv6";
	}
	return "?";
}

// Check if address family value is valid.
static inline bool gr_af_valid(addr_family_t af) {
	switch (af) {
	case GR_AF_UNSPEC:
	case GR_AF_IP4:
	case GR_AF_IP6:
		return true;
	}
	return false;
}

// Custom printf specifiers for network addresses.

// struct rte_ether_addr *
#define ETH_F "%2p"
// ip4_addr_t *
#define IP4_F "%4p"
// struct rte_ipv6_addr *
#define IP6_F "%6p"
// Either ETH_F, IP4 or IP6 depending on the width argument
#define ADDR_F "%*p"

#define ADDR_W(family) (family == AF_INET ? 4 : (family == AF_INET6 ? 6 : 0))

#define ETH_ADDR_RE "^[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}$"

#define IPV4_ATOM "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
#define __IPV4_RE IPV4_ATOM "(\\." IPV4_ATOM "){3}"
#define __IPV4_PREFIX_RE "/(3[0-2]|[12][0-9]|[0-9])"
#define IPV4_RE "^" __IPV4_RE "$"
#define IPV4_NET_RE "^" __IPV4_RE __IPV4_PREFIX_RE "$"

// IPv4 address type (network byte order).
typedef uint32_t ip4_addr_t;

// IPv4 network with prefix length.
struct ip4_net {
	ip4_addr_t ip;
	uint8_t prefixlen;
};

// Check if two IPv4 addresses are in the same subnet.
static inline bool ip4_addr_same_subnet(ip4_addr_t a, ip4_addr_t b, uint8_t prefixlen) {
	ip4_addr_t mask = htonl(~(UINT32_MAX >> prefixlen));
	return ((a ^ b) & mask) == 0;
}

#define IPV4_ADDR_BCAST RTE_BE32(0xffffffff)

// Check if the provided IPv4 address is multicast.
static inline bool ip4_addr_is_mcast(const ip4_addr_t ip) {
	const union {
		ip4_addr_t ip;
		uint8_t u8[4];
	} addr = {.ip = ip};
	return addr.u8[0] >= 224 && addr.u8[0] <= 239;
}

// Parse IPv4 network string (e.g. "192.168.1.0/24") into ip4_net structure.
static inline int ip4_net_parse(const char *s, struct ip4_net *net, bool zero_mask) {
	char *addr = NULL;
	int ret = -1;

	if (sscanf(s, "%m[0-9.]/%hhu%*c", &addr, &net->prefixlen) != 2) {
		errno = EINVAL;
		goto out;
	}
	if (net->prefixlen > 32) {
		errno = EINVAL;
		goto out;
	}
	if (inet_pton(AF_INET, addr, &net->ip) != 1) {
		errno = EINVAL;
		goto out;
	}
	if (zero_mask) {
		// mask non network bits to zero
		net->ip &= htonl((uint32_t)(UINT64_MAX << (32 - net->prefixlen)));
	}
	ret = 0;
out:
	free(addr);
	return ret;
}

#define IPV6_ATOM "([A-Fa-f0-9]{1,4})"
#define __IPV6_RE "(" IPV6_ATOM "|::?){2,15}(:" IPV6_ATOM "(\\." IPV4_ATOM "){3})?"
#define __IPV6_PREFIX_RE "/(12[0-8]|1[01][0-9]|[1-9]?[0-9])"
#define IPV6_RE "^" __IPV6_RE "$"
#define IPV6_NET_RE "^" __IPV6_RE __IPV6_PREFIX_RE "$"

// IPv6 network with prefix length.
struct ip6_net {
	struct rte_ipv6_addr ip;
	uint8_t prefixlen;
};

// Parse IPv6 network string (e.g. "2001:db8::/32") into ip6_net structure.
static inline int ip6_net_parse(const char *s, struct ip6_net *net, bool zero_mask) {
	char *addr = NULL;
	int ret = -1;

	if (sscanf(s, "%m[A-Fa-f0-9:.]/%hhu%*c", &addr, &net->prefixlen) != 2) {
		errno = EINVAL;
		goto out;
	}
	if (net->prefixlen > RTE_IPV6_MAX_DEPTH) {
		errno = EINVAL;
		goto out;
	}
	if (inet_pton(AF_INET6, addr, &net->ip) != 1) {
		errno = EINVAL;
		goto out;
	}
	if (zero_mask) {
		// mask non network bits to zero
		rte_ipv6_addr_mask(&net->ip, net->prefixlen);
	}
	ret = 0;
out:
	free(addr);
	return ret;
}

#define IP_ANY_RE "^(" __IPV4_RE "|" __IPV6_RE ")$"
#define IP_ANY_NET_RE "^(" __IPV4_RE __IPV4_PREFIX_RE "|" __IPV6_RE __IPV6_PREFIX_RE ")$"
