// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include <gr_capture.h>

#include <pcap/bpf.h>

#include <stdatomic.h>
#include <stdint.h>
#include <sys/queue.h>

struct rte_bpf;

struct capture_session {
	struct gr_capture_ring *ring; // mmap'd memfd pointer
	int memfd;
	size_t memfd_size;
	uint32_t mmap_flags; // MAP_HUGETLB | MAP_HUGE_2MB or 0
	uint16_t capture_id;
	uint16_t iface_id; // GR_IFACE_ID_UNDEF = all
	gr_capture_dir_t direction;
	uint32_t snap_len;
	_Atomic uint64_t drops;
	_Atomic uint64_t bpf_passed; // packets that passed the BPF filter
	_Atomic uint64_t bpf_filtered; // packets rejected by BPF filter
	uint64_t (*bpf_jit_func)(void *); // JIT function pointer, NULL if not supported
	struct rte_bpf *bpf_jit;
	struct bpf_program bpf_prog;
	STAILQ_ENTRY(capture_session) next;
};

STAILQ_HEAD(capture_session_list, capture_session);
extern struct capture_session_list active_captures;

// Per-interface capture session pointer, read atomically by datapath.
extern _Atomic(struct capture_session *) iface_capture[GR_MAX_IFACES];

struct capture_session *capture_session_start(
	uint16_t iface_id,
	gr_capture_dir_t direction,
	uint32_t snap_len,
	const struct gr_capture_filter *filter
);
int capture_session_set_filter(uint16_t capture_id, const struct gr_capture_filter *);
void capture_session_stop(uint16_t capture_id);
struct capture_session *capture_session_find(uint16_t capture_id);
