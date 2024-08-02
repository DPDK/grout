// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_NET_TYPES
#define _GR_NET_TYPES

#include "gr_errno.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_ADDR_RE "^[[:xdigit:]]{2}(:[[:xdigit:]]{2}){5}$"
#define ETH_ADDR_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define ETH_ADDR_SPLIT(mac)                                                                        \
	(mac)->addr_bytes[0], (mac)->addr_bytes[1], (mac)->addr_bytes[2], (mac)->addr_bytes[3],    \
		(mac)->addr_bytes[4], (mac)->addr_bytes[5]

#define IPV4_ATOM "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
#define __IPV4_RE IPV4_ATOM "(\\." IPV4_ATOM "){3}"
#define IPV4_RE "^" __IPV4_RE "$"
#define IPV4_NET_RE "^" __IPV4_RE "/(3[0-2]|[12][0-9]|[0-9])$"
#define IP4_ADDR_FMT "%d.%d.%d.%d"
#if BYTE_ORDER == LITTLE_ENDIAN
#define IP4_ADDR_SPLIT(b) ((uint8_t *)b)[0], ((uint8_t *)b)[1], ((uint8_t *)b)[2], ((uint8_t *)b)[3]
#else
#define IP4_ADDR_SPLIT(b) ((uint8_t *)b)[3], ((uint8_t *)b)[2], ((uint8_t *)b)[1], ((uint8_t *)b)[0]
#endif

typedef uint32_t ip4_addr_t;

struct ip4_net {
	ip4_addr_t ip;
	uint8_t prefixlen;
};

static inline bool ip4_addr_same_subnet(ip4_addr_t a, ip4_addr_t b, uint8_t prefixlen) {
	ip4_addr_t mask = htonl(~(UINT32_MAX >> prefixlen));
	return ((a ^ b) & mask) == 0;
}

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

static inline int ip4_net_format(const struct ip4_net *net, char *buf, size_t len) {
	const char *tmp;
	int n;

	if ((tmp = inet_ntop(AF_INET, &net->ip, buf, len)) == NULL)
		return errno_set(EINVAL);

	n = strlen(tmp);
	return snprintf(buf + n, len - n, "/%u", net->prefixlen);
}

#endif
