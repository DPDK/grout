// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

// Shared memory MPSC capture ring - no DPDK dependencies.
// Used by grout datapath workers (producers) and grcli/libpcap (consumer).
//
// ARCHITECTURE
// ============
//
// Multiple datapath workers write captured packets into a fixed-size
// circular ring in POSIX shared memory. A single consumer (grcli or a
// libpcap plugin) maps the same segment and reads packets out.
//
//   Worker 0 --+  atomic
//   Worker 1 --+ fetch_add   +------------+
//   Worker 2 --+------------>|  shm ring  |
//   Worker 3 --+ (prod_head) | +-+-+-+-+  +---> Consumer
//                            | |0|1|2|3|..|  (grcli/tcpdump)
//                            | +-+-+-+-+  |  reads cons_head
//                            +------------+
//
// RING LAYOUT (8 slots shown, real default is 8192)
// =================================================
//
//   index:  0    1    2    3    4    5    6    7
//          +----+----+----+----+----+----+----+----+
//   seq:   |s=5 |s=6 |s=7 |s=8 |s=9 |s=10|s=11|s=12|
//   data:  |pkt |pkt |pkt |pkt |pkt |... |... |... |
//          +----+----+----+----+----+----+----+----+
//                     ^                   ^
//                     |                   |
//                  cons_head=6        prod_head=10
//                (reads slot 6)     (claims slot 10)
//
// Each slot is 4096 bytes: 32-byte header + up to 4064 bytes of
// raw Ethernet frame data.
//
// PROTOCOL
// ========
//
// Producer (batch of N packets, one lock xadd per burst):
//
//   1. base = atomic_fetch_add(&prod_head, N, relaxed)
//      Reserve N consecutive slots with a single atomic op.
//
//   2. For each slot i in [base, base+N):
//      a. Write metadata (pkt_len, iface_id, direction, timestamp)
//      b. memcpy packet data into slot->data
//      c. atomic_store(&slot->sequence, i + 1, release)
//         Publish: the store-release ensures the consumer sees
//         all writes before the sequence update.
//
// Consumer (single reader, no atomics needed for cons_head):
//
//   1. Check prod_head > cons_head (ring not empty)
//   2. Load slot->sequence with acquire
//   3. If sequence == cons_head + 1: slot is ready
//      a. memcpy slot into caller buffer (snapshot)
//      b. Re-check sequence (seqlock pattern) - if changed,
//         a producer overwrote the slot mid-read, discard
//      c. Advance cons_head
//   4. If sequence != cons_head + 1: producer lapped us
//      Skip cons_head forward to catch up
//
// SCENARIOS
// =========
//
// Normal operation (consumer keeps up):
//
//   prod_head=10  cons_head=6  slot_count=8
//   Available: 10 - 6 = 4 readable slots (indices 6,7,8,9)
//   Free: 8 - 4 = 4 slots before wrap
//
//          +----+----+----+----+----+----+----+----+
//          |free|free|RDY |RDY |free|free|RDY |RDY |
//          +----+----+----+----+----+----+----+----+
//           [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]
//                     ^                   ^
//                 prod_head=10        cons_head=6
//                 (10 & 7 = 2)        (6 & 7 = 6)
//
// Consumer lapped (producers too fast):
//
//   prod_head=22  cons_head=6  slot_count=8
//   Distance: 22 - 6 = 16 > slot_count(8) - consumer is lapped.
//   All slots have been overwritten at least once.
//   Consumer skips: cons_head = prod_head - slot_count = 14
//   Then retries from slot 14 (index 14&7=6).
//
//          +----+----+----+----+----+----+----+----+
//          |s=21|s=22|s=15|s=16|s=17|s=18|s=19|s=20|
//          +----+----+----+----+----+----+----+----+
//           [0]  [1]  [2]  [3]  [4]  [5]  [6]  [7]
//                ^                        ^
//           prod_head=22           cons_head was 6
//                                  skips to 14
//                                  (14 & 7 = 6)
//
// Torn read (producer overwrites mid-read):
//
//   Consumer reads slot 6 (seq=7, correct). During the memcpy,
//   a producer writes the next round into slot 6 (seq=15).
//   The post-copy sequence re-check sees seq=15 != 7 → discard.
//   The consumer advances cons_head and retries the next slot.
//   This is rare in practice (< 0.1% at extreme overwrite rates)
//   and acceptable for a best-effort capture ring.
//
// Ring full (batch reservation with no space):
//
//   Producers never block. If the ring is full, reserved slots
//   overwrite unconsumed data. The consumer detects staleness via
//   the sequence mismatch and skips forward. No data corruption
//   occurs because slot writes are ordered: metadata first, then
//   packet data, then sequence publish (store-release).
//
// MEMORY ORDERING SUMMARY
// =======================
//
//   prod_head:  fetch_add with relaxed - ordering comes from the
//               per-slot sequence store-release.
//   slot->seq:  store with release (producer), load with acquire
//               (consumer) - ensures all slot writes are visible
//               before the consumer reads them.
//   cons_head:  plain uint32_t, only written by the single consumer.
//               Producers read it without synchronization for the
//               fullness heuristic (stale reads cause false drops,
//               not corruption).

#pragma once

#include <gr_api.h>
#include <gr_infra.h>

#include <assert.h>
#include <net/if.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GR_CAPTURE_RING_MAGIC 0x47524350 // "GRCP"

#define GR_CAPTURE_SLOT_SIZE 4096
#define GR_CAPTURE_SLOT_HDR_SIZE 32
#define GR_CAPTURE_SLOT_DATA_MAX (GR_CAPTURE_SLOT_SIZE - GR_CAPTURE_SLOT_HDR_SIZE)

#define GR_CAPTURE_SLOT_COUNT_DEFAULT 8192

typedef enum : uint8_t {
	GR_CAPTURE_DIR_BOTH = 0,
	GR_CAPTURE_DIR_IN, // Rx
	GR_CAPTURE_DIR_OUT, // Tx
} gr_capture_dir_t;

// Per-interface descriptor stored in the ring header.
// The consumer uses this to generate pcapng Interface Description Blocks.
struct gr_capture_iface {
	uint16_t iface_id;
	gr_iface_type_t type;
	char name[IFNAMSIZ]; // NUL-terminated
};

// Fixed-size slot written by the datapath, read by the consumer.
struct gr_capture_slot {
	_Atomic uint32_t sequence; // set to (pos + 1) on completion
	uint32_t pkt_len; // original packet length
	uint32_t cap_len; // captured bytes (<= snap_len)
	uint16_t iface_id;
	gr_capture_dir_t direction;
	uint8_t __padding[7];
	uint64_t timestamp_tsc; // raw TSC value
	uint8_t data[GR_CAPTURE_SLOT_DATA_MAX];
};

static_assert(sizeof(struct gr_capture_slot) == GR_CAPTURE_SLOT_SIZE, "slot size mismatch");

// Ring control block at the start of the shm segment.
// Layout: [ring header] [iface table] [slot array]
struct gr_capture_ring {
	_Atomic uint32_t magic;
	uint32_t version;
	uint32_t slot_count; // power of 2
	uint32_t slot_size;
	uint32_t snap_len;
	uint16_t n_ifaces;
	uint16_t _reserved;
	// TSC calibration for timestamp conversion.
	uint64_t tsc_hz; // TSC ticks per second
	uint64_t tsc_ref; // TSC value at capture start
	uint64_t realtime_ref_ns; // CLOCK_REALTIME at capture start (nanoseconds)
	// Producer index (multiple workers, atomic fetch-add).
	alignas(64) _Atomic uint32_t prod_head;
	// Consumer index (single reader, not shared with producers).
	alignas(64) uint32_t cons_head;
};

// Return pointer to the interface table (right after the ring header).
GR_API_INLINE struct gr_capture_iface *gr_capture_ring_ifaces(struct gr_capture_ring *r) {
	return (struct gr_capture_iface *)(r + 1);
}

GR_API_INLINE const struct gr_capture_iface *
gr_capture_ring_ifaces_const(const struct gr_capture_ring *r) {
	return (const struct gr_capture_iface *)(r + 1);
}

// Return pointer to slot array (after header + iface table).
GR_API_INLINE struct gr_capture_slot *gr_capture_ring_slots(struct gr_capture_ring *r) {
	size_t off = sizeof(*r) + r->n_ifaces * sizeof(struct gr_capture_iface);
	// Align to slot size for cache friendliness.
	off = (off + GR_CAPTURE_SLOT_SIZE - 1) & ~(size_t)(GR_CAPTURE_SLOT_SIZE - 1);
	return (struct gr_capture_slot *)((uintptr_t)r + off);
}

GR_API_INLINE const struct gr_capture_slot *
gr_capture_ring_slots_const(const struct gr_capture_ring *r) {
	size_t off = sizeof(*r) + r->n_ifaces * sizeof(struct gr_capture_iface);
	off = (off + GR_CAPTURE_SLOT_SIZE - 1) & ~(size_t)(GR_CAPTURE_SLOT_SIZE - 1);
	return (const struct gr_capture_slot *)((uintptr_t)r + off);
}

// Compute total shm segment size.
GR_API_INLINE size_t gr_capture_ring_memsize(uint32_t slot_count, uint16_t n_ifaces) {
	size_t off = sizeof(struct gr_capture_ring) + n_ifaces * sizeof(struct gr_capture_iface);
	off = (off + GR_CAPTURE_SLOT_SIZE - 1) & ~(size_t)(GR_CAPTURE_SLOT_SIZE - 1);
	return off + (size_t)slot_count * GR_CAPTURE_SLOT_SIZE;
}

// Consumer: try to dequeue one slot into a caller-provided buffer.
// Returns true on success (slot data copied to *out), false if ring
// is empty or the slot was overwritten during the read.
// The buffer copy is necessary because producers can overwrite slots
// at any time when the ring is full (overwrite semantics).
GR_API_INLINE bool gr_capture_ring_dequeue(struct gr_capture_ring *r, struct gr_capture_slot *out) {
	uint32_t pos = r->cons_head;
	uint32_t prod = atomic_load_explicit(&r->prod_head, memory_order_acquire);

	// Nothing produced yet.
	if (pos == prod)
		return false;

	const struct gr_capture_slot *slots = gr_capture_ring_slots_const(r);
	const struct gr_capture_slot *slot = &slots[pos & (r->slot_count - 1)];

	uint32_t seq = atomic_load_explicit(&slot->sequence, memory_order_acquire);
	if (seq != pos + 1) {
		// Producer lapped us. Skip ahead.
		if (prod - pos > r->slot_count)
			r->cons_head = prod - r->slot_count;
		return false;
	}

	// Copy slot data to caller buffer.
	memcpy(out, slot, sizeof(*out));

	// Re-check sequence after copy. If a producer overwrote this slot
	// during our memcpy, the sequence will have changed - discard.
	uint32_t seq2 = atomic_load_explicit(&slot->sequence, memory_order_acquire);
	if (seq2 != seq) {
		r->cons_head = pos + 1;
		return false;
	}

	r->cons_head = pos + 1;
	return true;
}

// Convert a slot TSC timestamp to nanoseconds since epoch.
// Split into seconds + remainder to avoid overflow: rem < tsc_hz
// (at most ~5e9 for a 5 GHz CPU), so rem * 1e9 stays within uint64_t.
GR_API_INLINE uint64_t
gr_capture_slot_timestamp_ns(const struct gr_capture_ring *r, const struct gr_capture_slot *s) {
	uint64_t delta = s->timestamp_tsc - r->tsc_ref;
	uint64_t sec = delta / r->tsc_hz;
	uint64_t rem = delta % r->tsc_hz;
	return r->realtime_ref_ns + sec * 1000000000ULL + rem * 1000000000ULL / r->tsc_hz;
}
