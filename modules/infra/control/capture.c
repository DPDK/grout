// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Vincent Jardin, Free Mobile

#include "capture.h"
#include "config.h"
#include "event.h"
#include "iface.h"
#include "log.h"
#include "module.h"
#include "rcu.h"

#include <gr_capture.h>
#include <gr_string.h>

#include <pcap/bpf.h>
#include <rte_build_config.h>
#ifdef RTE_LIB_BPF
#include <rte_bpf.h>
#endif
#include <rte_cycles.h>
#include <rte_malloc.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/mman.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

LOG_TYPE("capture");

#define CAPTURE_SNAP_MAX 4096

_Atomic(struct capture_session *) iface_capture[GR_MAX_IFACES];

struct capture_session_list active_captures = STAILQ_HEAD_INITIALIZER(active_captures);

static void capture_set_flags(struct capture_session *s) {
	if (s->iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(s->iface_id);
		if (iface != NULL) {
			iface->flags |= GR_IFACE_F_CAPTURE;
			atomic_store_explicit(&iface_capture[iface->id], s, memory_order_release);
		}
	} else {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			iface->flags |= GR_IFACE_F_CAPTURE;
			atomic_store_explicit(&iface_capture[iface->id], s, memory_order_release);
		}
	}
}

static void capture_clear_flags(struct capture_session *s) {
	if (s->iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(s->iface_id);
		if (iface != NULL) {
			iface->flags &= ~GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], NULL, memory_order_release
			);
		}
	} else {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			struct capture_session *cur = atomic_load_explicit(
				&iface_capture[iface->id], memory_order_relaxed
			);
			if (cur != s)
				continue;
			iface->flags &= ~GR_IFACE_F_CAPTURE;
			atomic_store_explicit(
				&iface_capture[iface->id], NULL, memory_order_release
			);
		}
	}
}

static void iface_add_callback(uint32_t /*event*/, const void *obj) {
	const struct iface *iface = obj;
	struct capture_session *s;

	STAILQ_FOREACH (s, &active_captures, next) {
		if (s->iface_id != GR_IFACE_ID_UNDEF)
			continue;
		iface_from_id(iface->id)->flags |= GR_IFACE_F_CAPTURE;
		atomic_store_explicit(&iface_capture[iface->id], s, memory_order_release);
		return;
	}
}

struct capture_session *capture_session_find(uint16_t capture_id) {
	struct capture_session *s;
	STAILQ_FOREACH (s, &active_captures, next) {
		if (s->capture_id == capture_id)
			return s;
	}
	return NULL;
}

static int install_bpf_filter(struct capture_session *s, const struct gr_capture_filter *filter) {
	struct bpf_program prog = {.bf_len = filter->n_instructions, .bf_insns = NULL};
	uint64_t (*jit_func)(void *) = NULL;

	if (prog.bf_len > 0) {
		prog.bf_insns = calloc(filter->n_instructions, sizeof(*prog.bf_insns));
		if (prog.bf_insns == NULL)
			return errno_set(ENOMEM);
		memcpy(prog.bf_insns, filter->instructions, prog.bf_len * sizeof(*prog.bf_insns));
	}

#ifdef RTE_LIB_BPF
	struct rte_bpf *bpf = NULL;
	if (prog.bf_len > 0) {
		struct rte_bpf_prm *prm = rte_bpf_convert(&prog);
		if (prm == NULL) {
			LOG(ERR, "rte_bpf_convert: %s", rte_strerror(rte_errno));
			free(prog.bf_insns);
			return errno_set(rte_errno);
		}

		bpf = rte_bpf_load(prm);
		rte_free(prm);
		if (bpf == NULL) {
			LOG(ERR, "rte_bpf_load: %s", rte_strerror(rte_errno));
			free(prog.bf_insns);
			return errno_set(rte_errno);
		}

		struct rte_bpf_jit jit = {.func = NULL};
		if (rte_bpf_get_jit(bpf, &jit) < 0 || jit.func == NULL) {
			LOG(NOTICE, "BPF JIT not available, using interpreter");
		} else {
			jit_func = jit.func;
		}
	}
	rte_bpf_destroy(s->bpf_jit);
	s->bpf_jit = bpf;
#endif

	struct bpf_insn *prev_instructions = s->bpf_prog.bf_insns;
	s->bpf_prog = prog;
	s->bpf_jit_func = jit_func;
	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);
	free(prev_instructions);

	LOG(INFO,
	    "capture filter installed (%u instructions, JIT %s)",
	    filter->n_instructions,
	    jit_func ? "enabled" : "disabled");

	return 0;
}

struct capture_session *capture_session_start(
	uint16_t iface_id,
	gr_capture_dir_t direction,
	uint32_t snap_len,
	const struct gr_capture_filter *filter
) {
	struct capture_session *s;

	if (iface_id != GR_IFACE_ID_UNDEF) {
		struct iface *iface = iface_from_id(iface_id);
		if (iface == NULL) {
			errno = ENODEV;
			return NULL;
		}
		if (atomic_load_explicit(&iface_capture[iface_id], memory_order_relaxed) != NULL) {
			errno = EBUSY;
			return NULL;
		}
	} else {
		struct iface *iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			if (atomic_load_explicit(&iface_capture[iface->id], memory_order_relaxed)
			    != NULL) {
				errno = EBUSY;
				return NULL;
			}
		}
	}

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;

	s->memfd = -1;
	s->iface_id = iface_id;
	s->direction = direction;
	s->snap_len = snap_len ? snap_len : CAPTURE_SNAP_MAX;
	if (s->snap_len > GR_CAPTURE_SLOT_DATA_MAX)
		s->snap_len = GR_CAPTURE_SLOT_DATA_MAX;

	// Count interfaces for the IDB table. For a specific iface
	// capture, only that interface is listed. For "any", all are.
	uint16_t n_ifaces = 0;
	struct iface *iface = NULL;
	if (iface_id != GR_IFACE_ID_UNDEF) {
		n_ifaces = 1;
	} else {
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			switch (iface->type) {
			case GR_IFACE_TYPE_VRF:
			case GR_IFACE_TYPE_IPIP:
				break;
			default:
				n_ifaces++;
				break;
			}
		}
	}

	uint32_t slot_count = GR_CAPTURE_SLOT_COUNT_DEFAULT;
	s->memfd_size = gr_capture_ring_memsize(slot_count, n_ifaces);

	unsigned memfd_flags = MFD_CLOEXEC;
	if (!gr_config.test_mode) {
		memfd_flags |= MFD_HUGETLB | MFD_HUGE_2MB;
		s->mmap_flags = MAP_HUGETLB | MAP_HUGE_2MB;
	}

	s->memfd = memfd_create("grout-capture", memfd_flags);
	if (s->memfd < 0) {
		LOG(ERR, "memfd_create: %s", strerror(errno));
		goto err_free;
	}
	if (ftruncate(s->memfd, s->memfd_size) < 0) {
		LOG(ERR, "ftruncate: %s", strerror(errno));
		goto err_close;
	}

	// Seals are not supported with MFD_HUGETLB.
	if (gr_config.test_mode)
		fcntl(s->memfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL);

	s->ring = mmap(
		NULL, s->memfd_size, PROT_READ | PROT_WRITE, MAP_SHARED | s->mmap_flags, s->memfd, 0
	);
	if (s->ring == MAP_FAILED) {
		LOG(ERR, "mmap: %s", strerror(errno));
		s->ring = NULL;
		goto err_close;
	}

	memset(s->ring, 0, s->memfd_size);
	s->ring->magic = GR_CAPTURE_RING_MAGIC;
	s->ring->version = GR_API_VERSION;
	s->ring->slot_count = slot_count;
	s->ring->slot_size = GR_CAPTURE_SLOT_SIZE;
	s->ring->snap_len = s->snap_len;
	s->ring->n_ifaces = n_ifaces;
	s->ring->tsc_hz = rte_get_tsc_hz();
	s->ring->tsc_ref = rte_rdtsc();
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	s->ring->realtime_ref_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	struct gr_capture_iface *itbl = gr_capture_ring_ifaces(s->ring);
	if (iface_id != GR_IFACE_ID_UNDEF) {
		iface = iface_from_id(iface_id);
		itbl[0].iface_id = iface->id;
		itbl[0].type = iface->type;
		gr_strcpy(itbl[0].name, sizeof(itbl[0].name), iface->name);
	} else {
		uint16_t n = 0;
		iface = NULL;
		while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
			switch (iface->type) {
			case GR_IFACE_TYPE_VRF:
			case GR_IFACE_TYPE_IPIP:
				break;
			default:
				itbl[n].iface_id = iface->id;
				itbl[n].type = iface->type;
				gr_strcpy(itbl[n].name, sizeof(itbl[n].name), iface->name);
				n++;
				break;
			}
		}
		s->ring->n_ifaces = n;
	}

	if (filter != NULL && filter->n_instructions > 0) {
		if (install_bpf_filter(s, filter) < 0)
			goto err_unmap;
	}

	static uint16_t capture_seq;
	s->capture_id = ++capture_seq;
	STAILQ_INSERT_TAIL(&active_captures, s, next);
	capture_set_flags(s);

	event_push(
		GR_EVENT_CAPTURE_START,
		&(struct gr_capture_info) {
			.capture_id = s->capture_id,
			.direction = s->direction,
			.iface_id = s->iface_id,
			.pkt_count = s->bpf_passed,
			.drops = s->drops,
		}
	);

	LOG(INFO,
	    "capture %u started iface_id=%u direction=%u snap_len=%u",
	    s->capture_id,
	    iface_id,
	    direction,
	    s->snap_len);
	return s;

err_unmap:
	munmap(s->ring, s->memfd_size);
err_close:
	close(s->memfd);
err_free:
	free(s);
	return NULL;
}

int capture_session_set_filter(uint16_t capture_id, const struct gr_capture_filter *filter) {
	struct capture_session *s = capture_session_find(capture_id);
	if (s == NULL)
		return errno_set(ENOENT);

	if (install_bpf_filter(s, filter) < 0)
		return errno_set(errno);

	return 0;
}

void capture_session_stop(uint16_t capture_id) {
	struct capture_session *s = capture_session_find(capture_id);
	if (s == NULL)
		return;

	capture_clear_flags(s);
	STAILQ_REMOVE(&active_captures, s, capture_session, next);

	rte_rcu_qsbr_synchronize(gr_datapath_rcu(), RTE_QSBR_THRID_INVALID);

	event_push(
		GR_EVENT_CAPTURE_STOP,
		&(struct gr_capture_info) {
			.capture_id = capture_id,
			.direction = s->direction,
			.iface_id = s->iface_id,
			.pkt_count = s->bpf_passed,
			.drops = s->drops,
		}
	);

#ifdef RTE_LIB_BPF
	rte_bpf_destroy(s->bpf_jit);
#endif
	free(s->bpf_prog.bf_insns);

	uint64_t bpf_passed = atomic_load(&s->bpf_passed);
	uint64_t bpf_filtered = atomic_load(&s->bpf_filtered);

	if (s->ring != NULL) {
		// Signal consumers that the session is gone. Consumers
		// check ring->magic in their poll loop and exit when
		// it changes. The mmap survives close so this write
		// is visible to any process still mapped.
		s->ring->magic = 0;
		munmap(s->ring, s->memfd_size);
	}
	if (s->memfd >= 0)
		close(s->memfd);
	free(s);

	LOG(INFO,
	    "capture %u stopped (bpf_passed=%lu bpf_filtered=%lu)",
	    capture_id,
	    bpf_passed,
	    bpf_filtered);
}

uint64_t capture_dynflag;

static void capture_init(struct event_base *) {
	const struct rte_mbuf_dynflag flag = {.name = "gr_captured"};
	int bit = rte_mbuf_dynflag_register(&flag);
	if (bit < 0)
		ABORT("rte_mbuf_dynflag_register(gr_captured): %s", rte_strerror(rte_errno));
	capture_dynflag = UINT64_C(1) << bit;
}

static void capture_fini(struct event_base *) {
	struct capture_session *s;
	while ((s = STAILQ_FIRST(&active_captures)) != NULL)
		capture_session_stop(s->capture_id);
}

static struct module module = {
	.name = "capture",
	.depends_on = "iface*,trace",
	.init = capture_init,
	.fini = capture_fini,
};

RTE_INIT(capture_constructor) {
	module_register(&module);
	event_subscribe(GR_EVENT_IFACE_POST_ADD, iface_add_callback);
	event_serializer(GR_EVENT_CAPTURE_START, NULL);
	event_serializer(GR_EVENT_CAPTURE_STOP, NULL);
}
