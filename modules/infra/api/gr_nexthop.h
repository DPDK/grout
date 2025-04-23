// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#ifndef _GR_NEXTHOP
#define _GR_NEXTHOP

#include <gr_bitops.h>
#include <gr_clock.h>
#include <gr_infra.h>
#include <gr_macro.h>
#include <gr_net_types.h>

// Supported flags on a nexthop.
typedef enum : uint16_t {
	GR_NH_F_PENDING = GR_BIT16(0), // Probe sent
	GR_NH_F_REACHABLE = GR_BIT16(1), // Probe reply received
	GR_NH_F_STALE = GR_BIT16(2), // Reachable lifetime expired, need refresh
	GR_NH_F_FAILED = GR_BIT16(3), // All probes sent without reply
	GR_NH_F_STATIC = GR_BIT16(4), // Configured by user
	GR_NH_F_LOCAL = GR_BIT16(5), // Local address
	GR_NH_F_GATEWAY = GR_BIT16(6), // Gateway route
	GR_NH_F_LINK = GR_BIT16(7), // Connected link route
	GR_NH_F_MCAST = GR_BIT16(8), // Multicast address
} gr_nh_flags_t;

typedef enum : uint8_t {
	GR_NH_IPV4 = 1,
	GR_NH_IPV6,
	GR_NH_SR6_IPV4,
	GR_NH_SR6_IPV6,
	GR_NH_TYPE_COUNT
} gr_nh_type_t;

//! Nexthop structure exposed to the API.
struct gr_nexthop {
	gr_nh_flags_t flags; //!< bit mask of GR_NH_F_*
	uint16_t vrf_id; //!< L3 VRF domain
	uint16_t iface_id; //!< interface associated with this nexthop
	struct rte_ether_addr mac; //!< link-layer address
	union {
		struct {
		} addr;
		ip4_addr_t ipv4;
		struct rte_ipv6_addr ipv6;
	};
	gr_nh_type_t type; //!< nexthop type
	uint8_t prefixlen; //!< only has meaning with GR_NH_F_LOCAL
	uint16_t held_pkts; //!< number of packets waiting for resolution
	clock_t last_reply; //!< timestamp when last update was received
};

//! Nexthop events.
typedef enum {
	NEXTHOP_EVENT_NEW = EVENT_TYPE(GR_INFRA_MODULE, 0x0100),
	NEXTHOP_EVENT_DELETE = EVENT_TYPE(GR_INFRA_MODULE, 0x0101),
	NEXTHOP_EVENT_UPDATE = EVENT_TYPE(GR_INFRA_MODULE, 0x0102),
} nexthop_event_t;

#define gr_nh_flags_foreach(f, flags)                                                              \
	for (gr_nh_flags_t __i = 0, f = GR_BIT16(0); __i < sizeof(gr_nh_flags_t) * CHAR_BIT;       \
	     f = GR_BIT16(++__i))                                                                  \
		if (flags & f)

// Return the name of a given flag value.
// When working with flag masks, each individual flags must be iterated upon.
static inline const char *gr_nh_flag_name(const gr_nh_flags_t flag) {
	switch (flag) {
	case GR_NH_F_PENDING:
		return "pending";
	case GR_NH_F_REACHABLE:
		return "reachable";
	case GR_NH_F_STALE:
		return "stale";
	case GR_NH_F_FAILED:
		return "failed";
	case GR_NH_F_STATIC:
		return "static";
	case GR_NH_F_LOCAL:
		return "local";
	case GR_NH_F_GATEWAY:
		return "gateway";
	case GR_NH_F_LINK:
		return "link";
	case GR_NH_F_MCAST:
		return "multicast";
	}
	return "";
}

// Get the address family value from a nexthop.
static inline uint8_t nh_af(const struct gr_nexthop *nh) {
	switch (nh->type) {
	case GR_NH_IPV4:
	case GR_NH_SR6_IPV4:
		return AF_INET;
	case GR_NH_IPV6:
	case GR_NH_SR6_IPV6:
		return AF_INET6;
	case GR_NH_TYPE_COUNT:
		break;
	}
	return 0;
}

// Route install origin values shared by IPv4 and IPv6.
// See NH_ORIGIN_* in sys/route/nhop.h (BSD) and RTPROT_* in zebra/rt_netlink.h (FRR).
typedef enum : uint8_t {
	GR_RT_ORIGIN_UNSPEC = 0, //!< (NH_ORIGIN_UNSPEC).
	GR_RT_ORIGIN_REDIRECT = 1, //!< Installed implicitly by ICMP redirect (NH_ORIGIN_REDIRECT).
	GR_RT_ORIGIN_LINK = 2, //!< Installed implicitly for local addresses (NH_ORIGIN_KERNEL).
	GR_RT_ORIGIN_BOOT = 3, //!< Installed at boot?? (NH_ORIGIN_BOOT).
	GR_RT_ORIGIN_USER = 4, //!< Installed explicitly by user (NH_ORIGIN_STATIC).
	// Values 5 to 254 are allowed and are used by routing daemons.
	GR_RT_ORIGIN_GATED = 8, // (RTPROT_GATED)
	GR_RT_ORIGIN_RA = 9, // (RTPROT_RA)
	GR_RT_ORIGIN_MRT = 10, // (RTPROT_MRT)
	GR_RT_ORIGIN_ZEBRA = 11, // (RTPROT_ZEBRA)
	GR_RT_ORIGIN_BIRD = 12, // (RTPROT_BIRD)
	GR_RT_ORIGIN_DNROUTED = 13, // (RTPROT_DNROUTED)
	GR_RT_ORIGIN_XORP = 14, // (RTPROT_XORP)
	GR_RT_ORIGIN_NTK = 15, // (RTPROT_NTK)
	GR_RT_ORIGIN_DHCP = 16, // (RTPROT_DHCP)
	GR_RT_ORIGIN_MROUTED = 17, // (RTPROT_MROUTED)
	GR_RT_ORIGIN_KEEPALIVED = 18, // (RTPROT_KEEPALIVED)
	GR_RT_ORIGIN_BABEL = 42, // (RTPROT_BABEL)
	GR_RT_ORIGIN_OPENR = 99, // (RTPROT_OPENR)
	GR_RT_ORIGIN_BGP = 186, // (RTPROT_BGP)
	GR_RT_ORIGIN_ISIS = 187, // (RTPROT_ISIS)
	GR_RT_ORIGIN_OSPF = 188, // (RTPROT_OSPF)
	GR_RT_ORIGIN_RIP = 189, // (RTPROT_RIP)
	GR_RT_ORIGIN_RIPNG = 190, // (RTPROT_RIPNG from zebra)
	GR_RT_ORIGIN_NHRP = 191, // (RTPROT_NHRP from zebra)
	GR_RT_ORIGIN_EIGRP = 192, // (RTPROT_EIGRP)
	GR_RT_ORIGIN_LDP = 193, // (RTPROT_LDP from zebra)
	GR_RT_ORIGIN_SHARP = 194, // (RTPROT_SHARP from zebra)
	GR_RT_ORIGIN_PBR = 195, // (RTPROT_PBR from zebra)
	GR_RT_ORIGIN_ZSTATIC = 196, // (RTPROT_ZSTATIC from zebra)
	GR_RT_ORIGIN_OPENFABRIC = 197, // (RTPROT_OPENFABIC from zebra)
	GR_RT_ORIGIN_SRTE = 198, // (RTPROT_SRTE from zebra)
	GR_RT_ORIGIN_INTERNAL = 255, //!< Reserved for internal use by grout.
} gr_rt_origin_t;

static inline const char *gr_rt_origin_name(gr_rt_origin_t origin) {
	switch (origin) {
	case GR_RT_ORIGIN_UNSPEC:
		return "";
	case GR_RT_ORIGIN_REDIRECT:
		return "redirect";
	case GR_RT_ORIGIN_LINK:
		return "link";
	case GR_RT_ORIGIN_BOOT:
		return "boot";
	case GR_RT_ORIGIN_USER:
		return "user";
	case GR_RT_ORIGIN_GATED:
		return "gated";
	case GR_RT_ORIGIN_RA:
		return "ra";
	case GR_RT_ORIGIN_MRT:
		return "mrt";
	case GR_RT_ORIGIN_ZEBRA:
		return "zebra";
	case GR_RT_ORIGIN_BIRD:
		return "bird";
	case GR_RT_ORIGIN_DNROUTED:
		return "dnrouted";
	case GR_RT_ORIGIN_XORP:
		return "xorp";
	case GR_RT_ORIGIN_NTK:
		return "ntk";
	case GR_RT_ORIGIN_DHCP:
		return "dhcp";
	case GR_RT_ORIGIN_MROUTED:
		return "mrouted";
	case GR_RT_ORIGIN_KEEPALIVED:
		return "keepalived";
	case GR_RT_ORIGIN_BABEL:
		return "babel";
	case GR_RT_ORIGIN_OPENR:
		return "openr";
	case GR_RT_ORIGIN_BGP:
		return "bgp";
	case GR_RT_ORIGIN_ISIS:
		return "isis";
	case GR_RT_ORIGIN_OSPF:
		return "ospf";
	case GR_RT_ORIGIN_RIP:
		return "rip";
	case GR_RT_ORIGIN_RIPNG:
		return "ripng";
	case GR_RT_ORIGIN_NHRP:
		return "nhrp";
	case GR_RT_ORIGIN_EIGRP:
		return "eigrp";
	case GR_RT_ORIGIN_LDP:
		return "ldp";
	case GR_RT_ORIGIN_SHARP:
		return "sharp";
	case GR_RT_ORIGIN_PBR:
		return "pbr";
	case GR_RT_ORIGIN_ZSTATIC:
		return "zebra_static";
	case GR_RT_ORIGIN_OPENFABRIC:
		return "openfabric";
	case GR_RT_ORIGIN_SRTE:
		return "srte";
	case GR_RT_ORIGIN_INTERNAL:
		return "INTERNAL";
	}
	return "?";
}

// nexthop config //////////////////////////////////////////////////////////////
struct gr_nexthop_config {
	//! Maximum number of nexthops for all address families (default: 128K).
	uint32_t max_count;
	//! Reachable next hop lifetime after last probe reply received (default: 20 min).
	uint32_t lifetime_reachable_sec;
	//! Unreachable next hop lifetime after last unreplied probe was sent (default: 1 min).
	uint32_t lifetime_unreachable_sec;
	//! Max number of packets to hold per next hop waiting for resolution (default: 256).
	uint16_t max_held_pkts;
	//! Max number of unicast probes to send after NH_LIFETIME_REACHABLE.
	uint8_t max_ucast_probes;
	//! Max number of multicast/broadcast probes to send after unicast probes failed.
	uint8_t max_bcast_probes;
};

#define GR_INFRA_NH_CONFIG_GET REQUEST_TYPE(GR_INFRA_MODULE, 0x0060)

// struct gr_infra_nh_config_get_req { };

struct gr_infra_nh_config_get_resp {
	BASE(gr_nexthop_config);
	uint32_t used_count;
};

#define GR_INFRA_NH_CONFIG_SET REQUEST_TYPE(GR_INFRA_MODULE, 0x0061)

struct gr_infra_nh_config_set_req {
	BASE(gr_nexthop_config);
};

// struct gr_infra_nh_config_set_resp { };

#endif
