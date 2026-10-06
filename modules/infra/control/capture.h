// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#pragma once

#include "clock.h"
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
struct api_ctx;

struct capture_session {
	struct gr_capture_ring *ring; // mmap'd memfd pointer
	// Ring layout bounds cached in private state. The memfd is writable by
	// clients, so its header must not be trusted by the datapath.
	struct gr_capture_slot *slots;
	uint32_t slot_count;
	int memfd;
	size_t memfd_size;
	uint16_t capture_id;
	uint16_t iface_id; // GR_IFACE_ID_UNDEF = all
	const struct api_ctx *owner; // API connection that started the capture
	gr_capture_dir_t direction;
	bool promisc; // enable promiscuous mode on captured ports
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
extern _Atomic(struct capture_session *) *iface_capture;

struct capture_session *capture_session_start(
	uint16_t iface_id,
	gr_capture_dir_t direction,
	gr_capture_flags_t flags,
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

// Copy len bytes starting at offset off from a (possibly segmented) mbuf into
// dst. rte_pktmbuf_read returns a pointer into the mbuf when the range is
// contiguous, so the copy must go through the returned pointer.
static inline void
capture_copy_data(uint8_t *dst, const struct rte_mbuf *m, uint32_t off, uint32_t len) {
	if (len == 0)
		return;
	const void *src = rte_pktmbuf_read(m, off, len, dst);
	if (src != NULL && src != dst)
		memcpy(dst, src, len);
}

static inline void
capture_enqueue(const struct iface *iface, const gr_capture_dir_t direction, struct rte_mbuf *m) {
	if (!(iface->flags & GR_IFACE_F_CAPTURE))
		return;
	if (m->ol_flags & capture_dynflag)
		return; // already captured

	struct capture_session *s = atomic_load_explicit(
		&iface_capture[iface->id], memory_order_relaxed
	);
	if (s == NULL)
		return;
	if (!(s->direction & direction))
		return; // direction filter mismatch

	// Slot array, count and snap length come from private session state, not
	// from the client-writable ring header.
	uint16_t vlan_id = iface_mbuf_data(m)->vlan_id;
	uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
	struct gr_capture_slot *slots = s->slots;
	struct gr_capture_ring *ring = s->ring;
	uint32_t mask = s->slot_count - 1;
	uint32_t snap = s->snap_len;
	bool match = false;

	if (s->bpf_jit_func != NULL) {
		match = s->bpf_jit_func(m);
	} else if (s->bpf_prog.bf_len != 0) {
		// The interpreter reads from the first segment only: advertise no
		// more accessible bytes than are actually contiguous.
		struct pcap_pkthdr h = {.caplen = rte_pktmbuf_data_len(m), .len = pkt_len};
		const unsigned char *data = rte_pktmbuf_mtod(m, const unsigned char *);
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
	slot->timestamp_ns = wallclock_ns();

	if (vlan_id != 0) {
		// The VLAN tag was stripped on rx and stored in mbuf metadata.
		// Rebuild the 802.1Q frame in the slot:
		//   [dst+src MAC][0x8100][TCI][original ethertype + payload]
		uint32_t macs = 2 * RTE_ETHER_ADDR_LEN;
		struct {
			rte_be16_t eth_type;
			rte_be16_t vlan_tci;
		} vlan_hdr = {
			.eth_type = RTE_BE16(RTE_ETHER_TYPE_VLAN),
			.vlan_tci = rte_cpu_to_be_16(vlan_id),
		};

		capture_copy_data(slot->data, m, 0, RTE_MIN(cap_len, macs));
		if (cap_len > macs)
			memcpy(slot->data + macs,
			       &vlan_hdr,
			       RTE_MIN(cap_len - macs, (uint32_t)sizeof(vlan_hdr)));
		if (cap_len > macs + sizeof(vlan_hdr))
			capture_copy_data(
				slot->data + macs + sizeof(vlan_hdr),
				m,
				macs,
				cap_len - macs - (uint32_t)sizeof(vlan_hdr)
			);
	} else {
		capture_copy_data(slot->data, m, 0, cap_len);
	}

	atomic_store_explicit(&slot->sequence, pos + 1, memory_order_release);
	m->ol_flags |= capture_dynflag;
}
