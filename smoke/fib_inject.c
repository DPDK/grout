// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

// clang-format: off
#include <gr_api_client_impl.h>
// clang-format: on

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Prefix length distribution entry: prefix length and its weight in
// parts per thousand. Weights must sum to 1000.
struct prefix_dist {
	uint8_t prefixlen;
	uint16_t weight; // parts per thousand
	uint32_t seq; // per-bucket sequence counter
};

// Real-world IPv4 BGP table prefix length distribution (2026 data).
// Source: CIDR report / bgp.potaroo.net
static struct prefix_dist ipv4_dist[] = {
	{16, 14, 0}, // 1.4%
	{17, 8, 0}, // 0.8%
	{18, 14, 0}, // 1.4%
	{19, 25, 0}, // 2.5%
	{20, 45, 0}, // 4.5%
	{21, 51, 0}, // 5.1%
	{22, 109, 0}, // 10.9%
	{23, 106, 0}, // 10.6%
	{24, 620, 0}, // 62.0%
	{32, 8, 0}, // 0.8% host routes
};

// Real-world IPv6 BGP table prefix length distribution (2026 data).
// Source: bgp.potaroo.net / APNIC
static struct prefix_dist ipv6_dist[] = {
	{32, 130, 0}, // 13.0%
	{36, 40, 0}, // 4.0%
	{40, 95, 0}, // 9.5%
	{44, 105, 0}, // 10.5%
	{48, 500, 0}, // 50.0%
	{128, 10, 0}, // 1.0% host routes
	{46, 50, 0}, // 5.0% misc prefix lengths
	{42, 40, 0}, // 4.0%
	{38, 30, 0}, // 3.0%
};

// Pick a prefix length from the distribution table and return its
// per-bucket sequence number. Uses deterministic round-robin across
// buckets based on route index modulo 1000.
static struct prefix_dist *pick_prefix(addr_family_t af, uint32_t index) {
	uint32_t slot = index % 1000;
	struct prefix_dist *dist;
	uint32_t cumulative = 0;
	unsigned len;

	switch (af) {
	case GR_AF_IP4:
		dist = ipv4_dist;
		len = ARRAY_DIM(ipv4_dist);
		break;
	case GR_AF_IP6:
		dist = ipv6_dist;
		len = ARRAY_DIM(ipv6_dist);
		break;
	default:
		abort();
	}

	for (size_t i = 0; i < len; i++) {
		cumulative += dist[i].weight;
		if (slot < cumulative)
			return &dist[i];
	}

	return &dist[len - 1];
}

// Number of distinct blackhole nexthops to create. Routes are spread
// across these round-robin to prevent DPDK's tbl8 recycling from
// collapsing groups that have a single homogeneous nexthop value.
// Real-world BGP tables have roughly 1 unique nexthop per 10 prefixes.
// 2048 is enough to defeat the optimization without being excessive.
#define NUM_NEXTHOPS 2048

static int create_nexthops(struct gr_api_client *c) {
	struct gr_nh_add_req req = {
		.exist_ok = false,
		.nh.type = GR_NH_T_BLACKHOLE,
		.nh.origin = GR_NH_ORIGIN_STATIC,
		.nh.vrf_id = GR_VRF_DEFAULT_ID,
	};

	for (unsigned id = 1; id < NUM_NEXTHOPS + 1; id++) {
		req.nh.nh_id = id;
		if (gr_api_client_send_recv(c, GR_NH_ADD, sizeof(req), &req, NULL) < 0) {
			perror("GR_NH_ADD");
			return -1;
		}
	}

	return 0;
}

static int inject_ipv4(struct gr_api_client *c, uint32_t count) {
	struct gr_ip4_route_add_req req = {
		.vrf_id = GR_VRF_DEFAULT_ID,
		.exist_ok = false,
		.origin = GR_NH_ORIGIN_STATIC,
	};

	for (uint32_t i = 0; i < count; i++) {
		struct prefix_dist *p = pick_prefix(GR_AF_IP4, i);
		uint32_t seq = p->seq++;

		// Generate a unique prefix for this bucket. Place the
		// sequence number in the high bits of the network portion
		// so that shorter prefixes don't overlap with each other.
		// Start at 1.x.x.x to avoid 0.0.0.0/0.
		uint32_t ip = (seq + 1) << (32 - p->prefixlen);
		req.dest.prefixlen = p->prefixlen;
		req.dest.ip = htonl(ip);
		req.nh_id = (i % NUM_NEXTHOPS) + 1;

		if (gr_api_client_send_recv(c, GR_IP4_ROUTE_ADD, sizeof(req), &req, NULL) < 0) {
			perror("GR_IP4_ROUTE_ADD");
			return -1;
		}
	}

	return 0;
}

static int inject_ipv6(struct gr_api_client *c, uint32_t count) {
	struct gr_ip6_route_add_req req = {
		.vrf_id = GR_VRF_DEFAULT_ID,
		.exist_ok = false,
		.origin = GR_NH_ORIGIN_STATIC,
	};

	for (uint32_t i = 0; i < count; i++) {
		struct prefix_dist *p = pick_prefix(GR_AF_IP6, i);
		uint32_t seq = p->seq++;

		memset(&req.dest.ip, 0, sizeof(req.dest.ip));
		req.dest.prefixlen = p->prefixlen;

		// Use a different /8 base per bucket. Then left-align (seq+1)
		// into the bits between the base and the prefix boundary.
		uint8_t bucket = (uint8_t)(p - ipv6_dist);
		req.dest.ip.a[0] = 0x20 + bucket;

		// Left-align (seq+1) into the network bits after the /8
		// base prefix. For a /N prefix, we need (N-8) unique bits.
		// Place the sequence counter in the top (N-8) bits after
		// byte 0 so each value produces a distinct prefix.
		uint32_t v = seq + 1;
		unsigned net_bits = p->prefixlen > 8 ? p->prefixlen - 8 : 1;
		// Compute which byte within a[1..15] each bit of v maps to.
		// Bit 0 of v should map to bit (net_bits-1) after byte 0.
		unsigned bit_offset = net_bits > 32 ? net_bits - 32 : 0;
		uint32_t shifted = v << (32 - net_bits + bit_offset);
		unsigned start = bit_offset / 8;
		req.dest.ip.a[1 + start] = (shifted >> 24) & 0xff;
		req.dest.ip.a[2 + start] = (shifted >> 16) & 0xff;
		req.dest.ip.a[3 + start] = (shifted >> 8) & 0xff;
		req.dest.ip.a[4 + start] = shifted & 0xff;
		req.nh_id = (i % NUM_NEXTHOPS) + 1;

		if (gr_api_client_send_recv(c, GR_IP6_ROUTE_ADD, sizeof(req), &req, NULL) < 0) {
			perror("GR_IP6_ROUTE_ADD");
			return -1;
		}
	}

	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s [-46] [-s SOCK] [-n COUNT]\n", prog);
	fprintf(stderr, "  -4         Inject IPv4 routes (default)\n");
	fprintf(stderr, "  -6         Inject IPv6 routes\n");
	fprintf(stderr, "  -s SOCK    API socket path (default: $GROUT_SOCK_PATH)\n");
	fprintf(stderr, "  -n COUNT   Number of routes to inject (default: 10000)\n");
}

int main(int argc, char **argv) {
	const char *sock_path = getenv("GROUT_SOCK_PATH");
	struct gr_api_client *c;
	unsigned count = 10000;
	uint32_t installed = 0;
	unsigned dist_count;
	bool ipv6 = false;
	float duration;
	clock_t time;
	int ret;
	int o;

	while ((o = getopt(argc, argv, "46s:n:h")) != -1) {
		switch (o) {
		case '4':
			break;
		case '6':
			ipv6 = true;
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'n':
			count = strtoul(optarg, NULL, 10);
			break;
		case 'h':
		default:
			usage(argv[0]);
			return o == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}
	if (sock_path == NULL)
		sock_path = GR_DEFAULT_SOCK_PATH;

	c = gr_api_client_connect(sock_path);
	if (c == NULL) {
		perror("gr_api_client_connect");
		return EXIT_FAILURE;
	}

	printf("injecting %u %s routes over %u nexthops\n",
	       count,
	       ipv6 ? "IPv6" : "IPv4",
	       NUM_NEXTHOPS);
	dist_count = ipv6 ? ARRAY_DIM(ipv6_dist) : ARRAY_DIM(ipv4_dist);
	for (unsigned i = 0; i < dist_count; i++) {
		struct prefix_dist *p = ipv6 ? &ipv6_dist[i] : &ipv4_dist[i];
		printf("/%-5hhu  %10u  %10.01f%%\n",
		       p->prefixlen,
		       count * p->weight / 1000,
		       (float)p->weight / 10.0);
	}

	if (create_nexthops(c) < 0)
		return EXIT_FAILURE;

	time = gr_clock_us();

	if (ipv6)
		ret = inject_ipv6(c, count);
	else
		ret = inject_ipv4(c, count);

	duration = (float)(gr_clock_us() - time) / (float)CLOCKS_PER_SEC;

	printf("total time: %.1fs (%.1f routes/s)\n", duration, (float)count / duration);

	if (ret == 0 && ipv6) {
		struct gr_ip6_fib_info_list_req r = {GR_VRF_DEFAULT_ID};
		const struct gr_fib6_info *info;
		int ret;

		gr_api_client_stream_foreach (info, ret, c, GR_IP6_FIB_INFO_LIST, sizeof(r), &r)
			installed = info->used_routes;
		if (ret < 0)
			perror("GR_IP6_FIB_INFO_LIST");
	} else if (ret == 0) {
		struct gr_ip4_fib_info_list_req r = {GR_VRF_DEFAULT_ID};
		const struct gr_fib4_info *info;

		gr_api_client_stream_foreach (info, ret, c, GR_IP4_FIB_INFO_LIST, sizeof(r), &r)
			installed = info->used_routes;
		if (ret < 0)
			perror("GR_IP4_FIB_INFO_LIST");
	}

	gr_api_client_disconnect(c);

	if (installed < count) {
		fprintf(stderr, "error: only %u routes where configured\n", installed);
		ret = -1;
	}

	return ret < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
