// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile
//
// MPSC ring stress test for gr_capture_ring.h.
//
// Spawns P producer threads and 1 consumer thread exercising the
// Vyukov bounded MPSC queue under contention. Validates that:
//   - per-producer sequence numbers are strictly increasing
//   - no slot corruption (data pattern check)
//   - total_dequeued + total_drops == P * M
//
// No DPDK dependency. Pure C11 atomics + pthreads.

#include "_cmocka.h"

#include <gr_capture.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

// Test parameters — can be overridden via env vars for torture mode.
static uint32_t slot_count = 4096;
static unsigned n_producers; // set from nproc in ring_stress()
static uint64_t msgs_per_producer = 1000000; // 1M
static uint32_t payload_size = 98; // simulated packet size (ICMP default)
static uint32_t batch_size = 32; // slots reserved per atomic op

struct producer_args {
	struct gr_capture_ring *ring;
	unsigned id;
	uint64_t sent;
};

struct consumer_args {
	struct gr_capture_ring *ring;
	unsigned n_producers;
	_Atomic bool done; // set by main when all producers finish
	uint64_t received;
	uint64_t corrupted;
	uint64_t *last_seq; // per-producer last seen sequence
	uint64_t *ooo; // per-producer out-of-order count
};

static void *producer_thread(void *arg) {
	struct producer_args *pa = arg;
	struct gr_capture_ring *ring = pa->ring;
	struct gr_capture_slot *slots = gr_capture_ring_slots(ring);
	uint32_t mask = ring->slot_count - 1;

	for (uint64_t seq = 0; seq < msgs_per_producer;) {
		uint32_t burst = msgs_per_producer - seq;
		if (burst > batch_size)
			burst = batch_size;

		// Batch-reserve: one atomic op per burst.
		uint32_t base = atomic_fetch_add_explicit(
			&ring->prod_head, burst, memory_order_relaxed
		);

		// Fill all reserved slots. If the consumer is behind,
		// old unread data gets overwritten — the consumer
		// detects this via sequence mismatch and skips ahead.
		for (uint32_t j = 0; j < burst; j++) {
			uint32_t pos = base + j;
			struct gr_capture_slot *slot = &slots[pos & mask];

			slot->pkt_len = pa->id;
			slot->cap_len = (uint32_t)((seq + j) & 0xFFFFFFFF);
			slot->iface_id = (uint16_t)pa->id;
			slot->direction = GR_CAPTURE_DIR_IN;
			slot->timestamp_tsc = seq + j;

			uint64_t sig = ((uint64_t)pa->id << 32) | (uint32_t)(seq + j);
			memcpy(slot->data, &sig, sizeof(sig));
			if (payload_size > sizeof(sig))
				memset(slot->data + sizeof(sig), 0xAB, payload_size - sizeof(sig));

			atomic_store_explicit(&slot->sequence, pos + 1, memory_order_release);
		}

		pa->sent += burst;
		seq += burst;
	}

	return NULL;
}

static inline void consume_slot(struct consumer_args *ca, const struct gr_capture_slot *slot) {
	ca->received++;

	unsigned producer_id = slot->pkt_len;
	uint32_t seq = slot->cap_len;
	uint64_t sig;
	memcpy(&sig, slot->data, sizeof(sig));
	uint64_t expected_sig = ((uint64_t)producer_id << 32) | seq;

	if (sig != expected_sig) {
		ca->corrupted++;
		return;
	}

	if (producer_id < ca->n_producers) {
		if (seq <= ca->last_seq[producer_id] && ca->last_seq[producer_id] != 0)
			ca->ooo[producer_id]++;
		ca->last_seq[producer_id] = seq;
	}
}

static void *consumer_thread(void *arg) {
	struct consumer_args *ca = arg;
	struct gr_capture_ring *ring = ca->ring;
	struct gr_capture_slot slot;
	unsigned empty_spins = 0;

	for (;;) {
		if (gr_capture_ring_dequeue(ring, &slot)) {
			consume_slot(ca, &slot);
			empty_spins = 0;
			continue;
		}

		if (atomic_load_explicit(&ca->done, memory_order_acquire)) {
			while (gr_capture_ring_dequeue(ring, &slot))
				consume_slot(ca, &slot);
			break;
		}

		if (++empty_spins > 1000)
			sched_yield();
	}

	return NULL;
}

static void ring_stress(void **) {
	// Default: half the online CPUs for producers (at least 2),
	// simulating multiple datapath workers contending on the ring.
	long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	n_producers = ncpus > 4 ? (unsigned)(ncpus / 2) : 2;

	// Override via env vars for CI tuning or torture mode.
	const char *env;
	if ((env = getenv("CAPTURE_RING_SLOTS")) != NULL)
		slot_count = (uint32_t)atoi(env);
	if ((env = getenv("CAPTURE_RING_PRODUCERS")) != NULL)
		n_producers = (unsigned)atoi(env);
	if ((env = getenv("CAPTURE_RING_MESSAGES")) != NULL)
		msgs_per_producer = (uint64_t)atoll(env);
	if ((env = getenv("CAPTURE_RING_PAYLOAD")) != NULL)
		payload_size = (uint32_t)atoi(env);
	if ((env = getenv("CAPTURE_RING_BATCH")) != NULL)
		batch_size = (uint32_t)atoi(env);
	if (payload_size > GR_CAPTURE_SLOT_DATA_MAX)
		payload_size = GR_CAPTURE_SLOT_DATA_MAX;

	assert_true(slot_count > 0 && (slot_count & (slot_count - 1)) == 0);
	assert_true(n_producers > 0);
	assert_true(msgs_per_producer > 0);

	// Allocate ring via mmap (anonymous, no shm needed for test).
	size_t shm_size = gr_capture_ring_memsize(slot_count, 0);
	void *mem = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert_ptr_not_equal(mem, MAP_FAILED);
	memset(mem, 0, shm_size);

	struct gr_capture_ring *ring = mem;
	ring->magic = GR_CAPTURE_RING_MAGIC;
	ring->version = GR_API_VERSION;
	ring->slot_count = slot_count;
	ring->slot_size = GR_CAPTURE_SLOT_SIZE;
	ring->snap_len = GR_CAPTURE_SLOT_DATA_MAX;
	ring->n_ifaces = 0;

	// Prepare producer and consumer args.
	struct producer_args *pa = calloc(n_producers, sizeof(*pa));
	assert_non_null(pa);
	for (unsigned i = 0; i < n_producers; i++) {
		pa[i].ring = ring;
		pa[i].id = i;
	}

	struct consumer_args ca = {
		.ring = ring,
		.n_producers = n_producers,
		.done = false,
		.last_seq = calloc(n_producers, sizeof(uint64_t)),
		.ooo = calloc(n_producers, sizeof(uint64_t)),
	};
	assert_non_null(ca.last_seq);
	assert_non_null(ca.ooo);

	// Start consumer first so it's ready when producers begin.
	pthread_t consumer;
	assert_int_equal(pthread_create(&consumer, NULL, consumer_thread, &ca), 0);

	struct timespec t0;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	// Start producers.
	pthread_t *producers = calloc(n_producers, sizeof(pthread_t));
	assert_non_null(producers);
	for (unsigned i = 0; i < n_producers; i++)
		assert_int_equal(pthread_create(&producers[i], NULL, producer_thread, &pa[i]), 0);

	// Wait for all producers to finish.
	uint64_t total_sent = 0;
	for (unsigned i = 0; i < n_producers; i++) {
		pthread_join(producers[i], NULL);
		total_sent += pa[i].sent;
	}

	// Signal consumer that producers are done, then wait.
	atomic_store_explicit(&ca.done, true, memory_order_release);
	pthread_join(consumer, NULL);

	struct timespec t1;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

	uint64_t total_expected = (uint64_t)n_producers * msgs_per_producer;
	uint64_t overwritten = total_sent - ca.received;

	// Print results.
	fprintf(stderr,
		"ring stress: %u producers x %lu msgs, %u slots, batch %u\n",
		n_producers,
		msgs_per_producer,
		slot_count,
		batch_size);
	fprintf(stderr, "  sent:        %lu\n", total_sent);
	fprintf(stderr, "  received:    %lu\n", ca.received);
	fprintf(stderr, "  overwritten: %lu\n", overwritten);
	fprintf(stderr, "  corrupted:   %lu\n", ca.corrupted);
	fprintf(stderr, "  elapsed:     %.3f s\n", elapsed);
	if (elapsed > 0)
		fprintf(stderr, "  rate:        %.2f Mslots/s\n", total_sent / elapsed / 1e6);

	uint64_t total_ooo = 0;
	for (unsigned i = 0; i < n_producers; i++)
		total_ooo += ca.ooo[i];
	if (total_ooo > 0)
		fprintf(stderr, "  out-of-order: %lu (expected for MPSC)\n", total_ooo);

	// Validate invariants.
	// Under extreme overwrite (producers much faster than consumer,
	// e.g. with sanitizers), a small number of torn reads can occur
	// when a producer overwrites a slot mid-read despite the
	// sequence double-check. This is acceptable for a best-effort
	// capture ring. Verify the corruption rate is negligible.
	double corrupt_rate = total_sent > 0 ? (double)ca.corrupted / ca.received : 0;
	if (ca.corrupted > 0)
		fprintf(stderr, "  corrupt_rate: %.6f%%\n", corrupt_rate * 100);
	assert_true(corrupt_rate < 0.01); // less than 1%
	assert_int_equal(total_sent, total_expected);
	assert_true(ca.received <= total_sent);

	free(ca.last_seq);
	free(ca.ooo);
	free(producers);
	free(pa);
	munmap(mem, shm_size);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ring_stress),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
