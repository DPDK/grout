// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include "iface.h"
#include "rxtx.h"

#include <gr_capture.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

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

// Dynamic ol_flags bit set on mbufs that have already been captured.
// Prevents double-capture when a packet traverses multiple capture points.
// Cleared automatically by rte_pktmbuf_reset() on mbuf alloc/rx.
extern uint64_t capture_dynflag;

static inline void
capture_enqueue(const struct iface *iface, gr_capture_dir_t direction, struct rte_mbuf *m) {
	if (!(iface->flags & GR_IFACE_F_CAPTURE))
		return;
	if (m->ol_flags & capture_dynflag)
		return; // already captured

	struct capture_session *s = atomic_load_explicit(
		&iface_capture[iface->id], memory_order_relaxed
	);
	if (s == NULL)
		return;

	struct gr_capture_ring *ring = s->ring;
	struct gr_capture_slot *slots = gr_capture_ring_slots(ring);
	uint16_t vlan_id = iface_mbuf_data(m)->vlan_id;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
	uint32_t mask = ring->slot_count - 1;
	uint32_t snap = ring->snap_len;
	uint64_t tsc = rte_rdtsc();
	bool match = false;
	uint32_t off = 0;

	if (s->bpf_jit_func != NULL) {
		match = s->bpf_jit_func(m);
	} else if (s->bpf_prog.bf_len != 0) {
		const unsigned char *data = rte_pktmbuf_mtod(m, const unsigned char *);
		struct pcap_pkthdr h = {.caplen = pkt_len, .len = pkt_len};
		match = pcap_offline_filter(&s->bpf_prog, &h, data);
	} else {
		match = true;
	}
	if (!match) {
		atomic_fetch_add_explicit(&s->bpf_filtered, 1, memory_order_relaxed);
		return;
	}

	atomic_fetch_add_explicit(&s->bpf_passed, 1, memory_order_relaxed);

	uint32_t pos = atomic_fetch_add_explicit(&ring->prod_head, 1, memory_order_acquire);
	struct gr_capture_slot *slot = &slots[pos & mask];
	if (vlan_id != 0)
		pkt_len += sizeof(struct rte_vlan_hdr);
	uint32_t cap_len = RTE_MIN(pkt_len, snap);

	slot->pkt_len = pkt_len;
	slot->cap_len = cap_len;
	slot->iface_id = iface->id;
	slot->direction = direction;
	slot->timestamp_tsc = tsc;

	if (vlan_id != 0) {
		// Copy dst+src MACs (12 bytes).
		memcpy(slot->data, rte_pktmbuf_mtod(m, void *), 2 * RTE_ETHER_ADDR_LEN);

		// Insert 802.1Q header: ethertype + TCI.
		struct {
			rte_be16_t eth_type;
			rte_be16_t vlan_tci;
		} vlan_hdr = {
			.eth_type = RTE_BE16(RTE_ETHER_TYPE_VLAN),
			.vlan_tci = rte_cpu_to_be_16(vlan_id),
		};
		memcpy(slot->data + off, &vlan_hdr, sizeof(vlan_hdr));

		off = 2 * RTE_ETHER_ADDR_LEN + sizeof(vlan_hdr);
	}

	if (rte_pktmbuf_is_contiguous(m))
		memcpy(slot->data + off, rte_pktmbuf_mtod_offset(m, void *, off), cap_len);
	else
		rte_pktmbuf_read(m, off, cap_len, slot->data);

	atomic_store_explicit(&slot->sequence, pos + 1, memory_order_release);
	m->ol_flags |= capture_dynflag;
}
