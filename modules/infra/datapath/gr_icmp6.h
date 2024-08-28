// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_DATAPATH_ICMP6
#define _GR_DATAPATH_ICMP6

#include <gr_macro.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip6.h>

#include <endian.h>
#include <stdint.h>

// ICMP6 packet types
typedef enum {
	ICMP6_TYPE_ECHO_REQUEST = UINT8_C(128),
	ICMP6_TYPE_ECHO_REPLY = UINT8_C(129),
	ICMP6_TYPE_ROUTER_SOLICIT = UINT8_C(133),
	ICMP6_TYPE_ROUTER_ADVERT = UINT8_C(134),
	ICMP6_TYPE_NEIGH_SOLICIT = UINT8_C(135),
	ICMP6_TYPE_NEIGH_ADVERT = UINT8_C(136),
	_ICMP6_TYPE_MAX = UINT8_C(0xff),
} __rte_packed icmp6_type_t;

// ICMP6 preamble
struct icmp6 {
	icmp6_type_t type;
	uint8_t code;
	rte_be16_t cksum;
} __rte_packed;

// ICMP6_TYPE_ECHO_REQUEST
struct icmp6_echo_request {
	rte_be16_t ident;
	rte_be16_t seqnum;
} __rte_packed;

// ICMP6_TYPE_ECHO_REPLY
struct icmp6_echo_reply {
	rte_be16_t ident;
	rte_be16_t seqnum;
} __rte_packed;

// ICMP6_TYPE_ROUTER_SOLICIT
struct icmp6_router_solicit {
	uint32_t __reserved;
} __rte_packed;

// ICMP6_TYPE_ROUTER_ADVERT
struct icmp6_router_advert {
	uint8_t cur_hoplim;
	uint8_t flags;
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t managed_addr : 1, other_config : 1, __unused_flags : 6;
#else
	uint8_t __unused_flags : 6, managed_addr : 1, other_config : 1;
#endif
	rte_be16_t lifetime;
	rte_be32_t reachable_time;
	rte_be32_t retrans_timer;
} __rte_packed;

// ICMP6_TYPE_NEIGH_SOLICIT
struct icmp6_neigh_solicit {
	uint32_t __reserved;
	struct rte_ipv6_addr target;
} __rte_packed;

// ICMP6_TYPE_NEIGH_ADVERT
struct icmp6_neigh_advert {
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t router : 1, solicited : 1, override : 1, __unused_flags : 5;
#else
	uint8_t __unused_flags : 5, override : 1, solicited : 1, router : 1;
#endif
	uint8_t __reserved;
	uint16_t __reserved2;
	struct rte_ipv6_addr target;
} __rte_packed;

// ICMP6 options

// option types
typedef enum {
	ICMP6_OPT_SRC_LLADDR = UINT8_C(1),
	ICMP6_OPT_TARGET_LLADDR = UINT8_C(2),
	ICMP6_OPT_PREFIX = UINT8_C(3),
	ICMP6_OPT_REDIRECT = UINT8_C(4),
	ICMP6_OPT_MTU = UINT8_C(5),
	_ICMP6_OPT_MAX = UINT8_C(0xff),
} __rte_packed icmp6_opt_t;

struct icmp6_opt {
	icmp6_opt_t type;
	uint8_t len;
} __rte_packed;

// size of an option payload in units of 8 bytes
// (add 7 and truncate down to the next multiple of 8)
#define ICMP6_OPT_LEN(len) ((((len) + 7) & UINT8_C(0xf8)) / 8)

// ICMP6_OPT_SRC_LLADDR | ICMP6_OPT_TARGET_LLADDR
struct icmp6_opt_lladdr {
	struct rte_ether_addr mac;
} __rte_aligned(2) __rte_packed;

static inline bool
icmp6_get_opt(const struct icmp6_opt *opt, size_t ip6_len, uint8_t type, void *value) {
	while (ip6_len >= 8 && opt != NULL) {
		if (opt->type != type)
			goto next;

		switch (opt->type) {
		case ICMP6_OPT_TARGET_LLADDR:
		case ICMP6_OPT_SRC_LLADDR:
			struct icmp6_opt_lladdr *ll = PAYLOAD(opt);
			rte_ether_addr_copy(&ll->mac, (struct rte_ether_addr *)value);
			return true;
		default:
			break;
		}
next:
		ip6_len -= opt->len * 8;
		opt = (struct icmp6_opt *)((char *)opt + (opt->len * 8));
	}
	return false;
}

#endif
