// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile, Iliad

// pcap-grout: libpcap capture plugin for grout (Graph Router).
//
// Connects to grout's UNIX API socket, sends CAPTURE_START to create
// a shared memory ring, then reads raw packets directly from the mmap'd
// ring. No DPDK dependency — uses only grout's public C API headers.
//
// Device names use the "grout:" prefix followed by the interface name:
//   tcpdump -i grout:p0
//   tcpdump -i grout:any
//
// The grout daemon must be running and the API socket must be accessible
// (default: /run/grout.sock, override via GROUT_SOCK_PATH env var).
//
// This file is a libpcap plugin (.so) loaded at runtime by the pcap-plugin
// plugin loader. It links against libpcap (-lpcap) and calls
// pcap_plugin_* functions instead of accessing pcap_t fields directly.

#include <gr_api_client_impl.h>
#include <gr_capture.h>

#include <pcap/pcap-plugin.h>
#include <pcap/pcap.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define GROUT_PREFIX "grout:"
#define GROUT_PREFIX_LEN strlen(GROUT_PREFIX)
#define GROUT_POLL_US 100

struct pcap_grout {
	struct gr_api_client *client;
	struct gr_capture_ring *ring;
	size_t ring_size;
	uint16_t capture_id;
	int nonblock;
	uint64_t pkt_recv;
	uint64_t pkt_drop;
	struct timeval required_select_timeout;
};

static void pcap_grout_close(pcap_t *p) {
	struct pcap_grout *pg = pcap_plugin_priv(p);

	if (pg->client) {
		struct gr_capture_stop_req req = {.capture_id = pg->capture_id};
		gr_api_client_send_recv(pg->client, GR_CAPTURE_STOP, sizeof(req), &req, NULL);
		gr_api_client_disconnect(pg->client);
		pg->client = NULL;
	}
	if (pg->ring != NULL && pg->ring != MAP_FAILED) {
		munmap(pg->ring, pg->ring_size);
		pg->ring = NULL;
	}
	pcap_plugin_cleanup_live(p);
}

static inline void grout_ts_to_timeval(
	const struct gr_capture_ring *ring,
	const struct gr_capture_slot *slot,
	struct timeval *tv
) {
	uint64_t ns = gr_capture_slot_timestamp_ns(ring, slot);
	tv->tv_sec = (time_t)(ns / 1000000000ULL);
	tv->tv_usec = (suseconds_t)((ns % 1000000000ULL) / 1000);
}

static int pcap_grout_dispatch(pcap_t *p, int max_cnt, pcap_handler cb, u_char *cb_arg) {
	struct pcap_grout *pg = pcap_plugin_priv(p);
	int timeout_ms = pcap_plugin_get_timeout(p);
	int snapshot = pcap_plugin_get_snapshot(p);
	struct pcap_pkthdr hdr;
	int waited_us = 0;
	int pkt_cnt = 0;

	if (max_cnt <= 0)
		max_cnt = INT_MAX;

	struct gr_capture_slot slot;

	while (pkt_cnt < max_cnt) {
		if (pcap_plugin_check_break_loop(p))
			return PCAP_ERROR_BREAK;

		// Session stopped by grout (magic zeroed).
		if (pg->ring->magic != GR_CAPTURE_RING_MAGIC)
			break;

		if (!gr_capture_ring_dequeue(pg->ring, &slot)) {
			if (pg->nonblock)
				break;
			if (timeout_ms > 0 && waited_us >= timeout_ms * 1000)
				break;
			usleep(GROUT_POLL_US);
			waited_us += GROUT_POLL_US;
			continue;
		}

		waited_us = 0;
		pg->pkt_recv++;

		uint32_t caplen = slot.cap_len;
		if (caplen > (uint32_t)snapshot)
			caplen = (uint32_t)snapshot;

		grout_ts_to_timeval(pg->ring, &slot, &hdr.ts);
		hdr.caplen = caplen;
		hdr.len = slot.pkt_len;

		struct bpf_insn *fcode = pcap_plugin_get_filter(p);
		if (fcode == NULL || pcap_plugin_filter(fcode, slot.data, slot.pkt_len, caplen)) {
			cb(cb_arg, &hdr, slot.data);
			pkt_cnt++;
		} else {
			pg->pkt_drop++;
		}
	}

	return pkt_cnt;
}

// Push the BPF filter to grout's datapath for JIT execution.
// Also install it locally as fallback for edge cases.
static int pcap_grout_setfilter(pcap_t *p, struct bpf_program *fp) {
	struct pcap_grout *pg = pcap_plugin_priv(p);

	// Install locally first (libpcap keeps a copy).
	if (pcap_plugin_install_bpf(p, fp) < 0)
		return PCAP_ERROR;

	if (pg->client == NULL)
		return 0;

	// Send the classic BPF bytecode to grout for datapath JIT.
	struct gr_capture_set_filter_req *req;
	size_t insn_bytes = fp->bf_len * sizeof(struct gr_bpf_instruction);
	size_t req_size = sizeof(*req) + insn_bytes;
	req = malloc(req_size);
	if (req == NULL)
		return 0; /* non-fatal: filter still runs locally */

	// Pack: uint16_t bpf_len + bpf_insn[]
	req->capture_id = pg->capture_id;
	req->filter.n_instructions = fp->bf_len;
	memcpy(req->filter.instructions, fp->bf_insns, insn_bytes);

	gr_api_client_send_recv(pg->client, GR_CAPTURE_SET_FILTER, req_size, req, NULL);
	free(req);

	// Ignore errors: worst case, filtering happens on the consumer
	// side only (the local BPF program is still installed).
	return 0;
}

static int pcap_grout_inject(pcap_t *p, const void * /*buf*/, int /*size*/) {
	pcap_plugin_set_errbuf(p, "grout: packet injection not supported");
	return PCAP_ERROR;
}

static int pcap_grout_stats(pcap_t *p, struct pcap_stat *ps) {
	struct pcap_grout *pg = pcap_plugin_priv(p);

	if (ps == NULL)
		return 0;

	ps->ps_recv = (u_int)pg->pkt_recv;
	ps->ps_drop = (u_int)pg->pkt_drop;
	ps->ps_ifdrop = 0;

	return 0;
}

static int pcap_grout_setnonblock(pcap_t *p, int nonblock) {
	struct pcap_grout *pg = pcap_plugin_priv(p);

	pg->nonblock = nonblock;

	return 0;
}

static int pcap_grout_getnonblock(pcap_t *p) {
	struct pcap_grout *pg = pcap_plugin_priv(p);

	return pg->nonblock;
}

// Resolve an interface name to a grout iface_id.
// "any" returns GR_IFACE_ID_UNDEF (capture all ports).
static int grout_resolve_iface(struct gr_api_client *client, const char *name, uint16_t *iface_id) {
	if (strcmp(name, "any") == 0) {
		*iface_id = GR_IFACE_ID_UNDEF;
		return 0;
	}

	struct gr_iface_get_req req;
	void *resp = NULL;

	memset(&req, 0, sizeof(req));
	req.iface_id = GR_IFACE_ID_UNDEF;
	snprintf(req.name, sizeof(req.name), "%s", name);

	if (gr_api_client_send_recv(client, GR_IFACE_GET, sizeof(req), &req, &resp) < 0)
		return -1;

	struct gr_iface_get_resp *r = resp;
	*iface_id = r->iface.id;
	free(resp);

	return 0;
}

static int pcap_grout_activate(pcap_t *p) {
	struct pcap_grout *pg = pcap_plugin_priv(p);
	int snapshot = pcap_plugin_get_snapshot(p);
	const char *sock_path, *ifname;
	uint16_t iface_id;
	int ret;

	ifname = pcap_plugin_get_device(p) + GROUT_PREFIX_LEN;
	if (*ifname == '\0') {
		pcap_plugin_set_errbuf(p, "grout: empty interface name");
		return PCAP_ERROR_NO_SUCH_DEVICE;
	}

	sock_path = getenv("GROUT_SOCK_PATH");
	if (sock_path == NULL)
		sock_path = GR_DEFAULT_SOCK_PATH;

	pg->client = gr_api_client_connect(sock_path);
	if (pg->client == NULL) {
		pcap_plugin_set_errbuf(
			p, "grout: cannot connect to %s: %s", sock_path, strerror(errno)
		);
		return PCAP_ERROR;
	}

	if (grout_resolve_iface(pg->client, ifname, &iface_id) < 0) {
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}

	struct gr_capture_start_resp cresp;
	struct gr_capture_start_req creq = {
		.iface_id = iface_id,
		.snap_len = snapshot,
	};
	int memfd = -1;

	void *resp = NULL;
	ret = gr_api_client_send_recv_fd(
		pg->client, GR_CAPTURE_START, sizeof(creq), &creq, &resp, &memfd
	);
	if (ret < 0) {
		pcap_plugin_set_errbuf(p, "grout: capture start failed: %s", strerror(errno));
		ret = PCAP_ERROR;
		goto fail;
	}
	memcpy(&cresp, resp, sizeof(cresp));
	free(resp);

	if (memfd < 0) {
		pcap_plugin_set_errbuf(p, "grout: server did not send capture fd");
		ret = PCAP_ERROR;
		goto fail;
	}
	pg->ring_size = cresp.memfd_size;
	pg->ring = mmap(
		NULL, pg->ring_size, PROT_READ | PROT_WRITE, MAP_SHARED | cresp.mmap_flags, memfd, 0
	);
	close(memfd);
	if (pg->ring == MAP_FAILED) {
		pcap_plugin_set_errbuf(p, "grout: mmap: %s", strerror(errno));
		pg->ring = NULL;
		ret = PCAP_ERROR;
		goto fail;
	}

	if (pg->ring->magic != GR_CAPTURE_RING_MAGIC) {
		pcap_plugin_set_errbuf(p, "grout: invalid capture ring magic");
		ret = PCAP_ERROR;
		goto fail;
	}

	pg->capture_id = cresp.capture_id;

	// Determine the link type from the captured interface. For
	// single-interface captures, use the interface's link type. For
	// "any" captures, default to Ethernet since libpcap's API only
	// supports a single link type per handle.
	int dlt = DLT_EN10MB;
	if (iface_id != GR_IFACE_ID_UNDEF) {
		const struct gr_capture_iface *ifaces = gr_capture_ring_ifaces_const(pg->ring);
		for (uint16_t i = 0; i < pg->ring->n_ifaces; i++) {
			if (ifaces[i].iface_id == iface_id) {
				switch (ifaces[i].type) {
				case GR_IFACE_TYPE_VRF:
				case GR_IFACE_TYPE_IPIP:
					dlt = DLT_RAW;
					break;
				default:
					break;
				}
				break;
			}
		}
	}
	pcap_plugin_set_linktype(p, dlt);
	if (snapshot <= 0 || snapshot > PCAP_PLUGIN_SNAPLEN_MAX)
		pcap_plugin_set_snapshot(p, PCAP_PLUGIN_SNAPLEN_MAX);

	struct pcap_plugin_ops ops = {
		.read = pcap_grout_dispatch,
		.inject = pcap_grout_inject,
		.setfilter = pcap_grout_setfilter,
		.getnonblock = pcap_grout_getnonblock,
		.setnonblock = pcap_grout_setnonblock,
		.stats = pcap_grout_stats,
		.cleanup = pcap_grout_close,
		.breakloop_func = pcap_plugin_breakloop,
	};
	pcap_plugin_set_ops(p, &ops);

	pg->required_select_timeout.tv_sec = 0;
	pg->required_select_timeout.tv_usec = GROUT_POLL_US;
	pcap_plugin_set_select_timeout(p, &pg->required_select_timeout);

	return 0;

fail:
	pcap_grout_close(p);
	return ret;
}

static pcap_t *pcap_grout_create(const char *device, char *ebuf, int *is_ours) {
	pcap_t *p;

	*is_ours = (strncmp(device, GROUT_PREFIX, GROUT_PREFIX_LEN) == 0);
	if (!*is_ours)
		return NULL;

	p = pcap_plugin_create_handle(ebuf, sizeof(struct pcap_grout));
	if (p == NULL)
		return NULL;

	pcap_plugin_set_activate(p, pcap_grout_activate);

	return p;
}

static int pcap_grout_findalldevs(pcap_if_list_t *devlistp, char *ebuf) {
	struct gr_api_client *client;
	const char *sock_path;

	sock_path = getenv("GROUT_SOCK_PATH");
	if (sock_path == NULL)
		sock_path = GR_DEFAULT_SOCK_PATH;

	client = gr_api_client_connect(sock_path);
	if (client == NULL)
		return 0; /* grout not running, no devices to report */

	struct gr_iface_list_req req = {.type = GR_IFACE_TYPE_UNDEF};
	const struct gr_iface *iface;
	char devname[64];
	char desc[128];
	int ret;

	gr_api_client_stream_foreach (iface, ret, client, GR_IFACE_LIST, sizeof(req), &req) {
		const char *type = gr_iface_type_name(iface->type);
		snprintf(devname, sizeof(devname), "%s%s", GROUT_PREFIX, iface->name);
		snprintf(
			desc,
			sizeof(desc),
			"grout %s interface %s \"%s\"",
			type,
			iface->name,
			iface->description
		);
		if (pcap_plugin_add_dev(devlistp, devname, 0, desc, ebuf) == NULL) {
			ret = PCAP_ERROR;
			break;
		}
	}

	if (ret >= 0) {
		snprintf(desc, sizeof(desc), "grout: capture on all interfaces");
		if (pcap_plugin_add_dev(devlistp, "grout:any", 0, desc, ebuf) == NULL)
			ret = PCAP_ERROR;
	}

	gr_api_client_disconnect(client);

	return (ret < 0) ? ret : 0;
}

// Plugin entry point — discovered by libpcap's pcap-plugin.c via dlsym().
extern struct pcap_plugin pcap_plugin_entry;
struct pcap_plugin pcap_plugin_entry = {
	.abi_version = PCAP_PLUGIN_ABI_VERSION,
	.name = "grout",
	.findalldevs = pcap_grout_findalldevs,
	.create = pcap_grout_create,
};
