// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include "cli.h"
#include "cli_event.h"
#include "cli_iface.h"
#include "pcapng.h"
#include "tty.h"

#include <gr_api.h>
#include <gr_capture.h>
#include <gr_infra.h>

#include <ecoli.h>
#include <pcap/pcap.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile sig_atomic_t capture_running;

static void capture_sigint(int /*sig*/) {
	capture_running = 0;
}

// Map iface_id to pcapng interface index (IDB order).
static int find_iface_idx(const struct gr_capture_ring *ring, uint16_t iface_id) {
	const struct gr_capture_iface *ifaces = gr_capture_ring_ifaces_const(ring);
	for (uint16_t i = 0; i < ring->n_ifaces; i++) {
		if (ifaces[i].iface_id == iface_id)
			return i;
	}
	return 0;
}

static cmd_status_t capture_dump(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_capture_start_req *req = NULL;
	struct gr_capture_start_resp resp;
	struct gr_iface *iface = NULL;
	void *resp_ptr = NULL;
	uint16_t link_type;
	size_t req_size;
	int memfd = -1;
	int ret;

	if (is_tty(stdout)) {
		errorf("stdout is a terminal, redirect to a file or pipe to tcpdump");
		errno = EBADF;
		return CMD_ERROR;
	}

	req_size = sizeof(*req);
	req = calloc(1, req_size);
	if (req == NULL)
		return CMD_ERROR;

	if (arg_str(p, "any") != NULL) {
		req->iface_id = GR_IFACE_ID_UNDEF;
		link_type = DLT_EN10MB;
	} else {
		iface = iface_from_name(c, arg_str(p, "NAME"));
		if (iface == NULL) {
			free(req);
			return CMD_ERROR;
		}
		req->iface_id = iface->id;
		switch (iface->type) {
		case GR_IFACE_TYPE_VRF:
		case GR_IFACE_TYPE_IPIP:
			link_type = DLT_RAW;
			break;
		default:
			link_type = DLT_EN10MB;
			break;
		}
		free(iface);
	}

	if (arg_u32(p, "SNAPLEN", &req->snap_len) < 0 && errno != ENOENT) {
		free(req);
		return CMD_ERROR;
	}

	uint32_t max_count = 0;
	if (arg_u32(p, "COUNT", &max_count) < 0 && errno != ENOENT) {
		free(req);
		return CMD_ERROR;
	}

	const char *filter = arg_str(p, "FILTER");
	if (filter != NULL) {
		pcap_t *pd = pcap_open_dead(link_type, req->snap_len ? req->snap_len : 65535);
		if (pd == NULL) {
			free(req);
			errno = ENOMEM;
			return CMD_ERROR;
		}
		struct bpf_program bpf = {0};
		if (pcap_compile(pd, &bpf, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
			errorf("pcap_compile: %s", pcap_geterr(pd));
			pcap_close(pd);
			free(req);
			errno = EINVAL;
			return CMD_ERROR;
		}
		pcap_close(pd);

		size_t insn_bytes = bpf.bf_len * sizeof(struct gr_bpf_instruction);
		req_size = sizeof(*req) + insn_bytes;
		req = realloc(req, req_size);
		if (req == NULL) {
			pcap_freecode(&bpf);
			errno = ENOMEM;
			return CMD_ERROR;
		}
		req->filter.n_instructions = bpf.bf_len;
		memcpy(req->filter.instructions, bpf.bf_insns, insn_bytes);
		pcap_freecode(&bpf);
	}

	// Send capture start and get memfd
	ret = gr_api_client_send_recv_fd(c, GR_CAPTURE_START, req_size, req, &resp_ptr, &memfd);
	free(req);
	if (ret < 0)
		return CMD_ERROR;

	memcpy(&resp, resp_ptr, sizeof(resp));
	free(resp_ptr);

	// Map the shared capture ring.
	struct gr_capture_ring *ring = mmap(
		NULL,
		resp.memfd_size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED | resp.mmap_flags,
		memfd,
		0
	);
	close(memfd);
	if (ring == MAP_FAILED) {
		errorf("mmap: %s", strerror(errno));
		goto stop;
	}
	if (ring->magic != GR_CAPTURE_RING_MAGIC) {
		errorf("invalid capture ring magic");
		munmap(ring, resp.memfd_size);
		goto stop;
	}

	// Write pcapng file header (SHB + IDBs).
	if (pcapng_write_shb(stdout) < 0) {
		munmap(ring, resp.memfd_size);
		goto stop;
	}
	const struct gr_capture_iface *ifaces = gr_capture_ring_ifaces_const(ring);
	for (uint16_t i = 0; i < ring->n_ifaces; i++) {
		if (pcapng_write_idb(stdout, ifaces + i, ring->snap_len) < 0) {
			munmap(ring, resp.memfd_size);
			goto stop;
		}
	}
	fflush(stdout);

	// Set up signal handlers to stop capture cleanly.
	// Use sigaction() without SA_RESTART so that usleep() is
	// interrupted and the loop checks capture_running promptly.
	struct sigaction sa = {.sa_handler = capture_sigint};
	struct sigaction old_int, old_term, old_pipe;
	sigaction(SIGINT, &sa, &old_int);
	sigaction(SIGTERM, &sa, &old_term);
	sigaction(SIGPIPE, &sa, &old_pipe);
	capture_running = 1;

	// Read loop: poll ring, format pcapng EPBs, write stdout.
	struct gr_capture_slot slot;
	uint32_t pkt_count = 0;
	while (capture_running && ring->magic == GR_CAPTURE_RING_MAGIC) {
		if (!gr_capture_ring_dequeue(ring, &slot)) {
			fflush(stdout);
			usleep(100);
			continue;
		}

		uint64_t ts_ns = gr_capture_slot_timestamp_ns(ring, &slot);
		int iface_idx = find_iface_idx(ring, slot.iface_id);

		ret = pcapng_write_epb(
			stdout,
			iface_idx,
			ts_ns,
			slot.cap_len,
			slot.pkt_len,
			slot.data,
			slot.direction
		);
		if (ret < 0)
			break;
		if (max_count > 0 && ++pkt_count >= max_count)
			break;
	}

	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
	sigaction(SIGPIPE, &old_pipe, NULL);
	munmap(ring, resp.memfd_size);

stop:
	struct gr_capture_stop_req stop_req = {.capture_id = resp.capture_id};
	gr_api_client_send_recv(c, GR_CAPTURE_STOP, sizeof(stop_req), &stop_req, NULL);
	return CMD_SUCCESS;
}

#define CAPTURE_CTX(root) CLI_CONTEXT(root, CTX_ARG("capture", "Packet capture."))

static int ctx_init(struct ec_node *root) {
	int ret;

	ret = CLI_COMMAND(
		CAPTURE_CTX(root),
		"(any|(iface NAME)) [(count COUNT),(snaplen SNAPLEN),(filter FILTER)]",
		capture_dump,
		"Capture packets and write pcapng to stdout.",
		with_help("All interfaces.", ec_node_str("any", "any")),
		with_help(
			"Interface name.",
			ec_node_dyn("NAME", complete_iface_names, INT2PTR(GR_IFACE_TYPE_UNDEF))
		),
		with_help(
			"Stop after COUNT packets (0 = unlimited).",
			ec_node_uint("COUNT", 0, UINT32_MAX, 10)
		),
		with_help(
			"Snap length in bytes (0 = full packet).",
			ec_node_uint("SNAPLEN", 0, UINT32_MAX, 10)
		),
		with_help("BPF filter expression (e.g. 'icmp').", ec_node("any", "FILTER"))
	);
	if (ret < 0)
		return ret;

	return 0;
}

static struct cli_context ctx = {
	.name = "capture",
	.init = ctx_init,
};

static void capture_event_print(uint32_t event, const void *obj) {
	const struct gr_capture_info *info = obj;
	const char *action;

	switch (event) {
	case GR_EVENT_CAPTURE_START:
		action = "start";
		break;
	case GR_EVENT_CAPTURE_STOP:
		action = "stop";
		break;
	default:
		action = "?";
		break;
	}

	printf("capture %s: id=%u iface=%u direction=%hhu packets=%lu\n",
	       action,
	       info->capture_id,
	       info->iface_id,
	       info->direction,
	       info->pkt_count);
}
static struct cli_event_printer printer = {
	.name = "capture",
	.print = capture_event_print,
	.ev_count = 2,
	.ev_types = {
		GR_EVENT_CAPTURE_START,
		GR_EVENT_CAPTURE_STOP,
	},
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
	cli_event_printer_register(&printer);
}
