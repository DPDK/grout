// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Red Hat, Inc.

#include "mbuf.h"

#include <rte_malloc.h>
#include <rte_mbuf.h>

static void extbuf_free_cb(void * /*addr*/, void *opaque) {
	rte_free(opaque);
}

struct rte_mbuf *gr_mbuf_alloc(struct rte_mempool *mp, uint32_t data_len) {
	struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
	struct rte_mbuf_ext_shared_info *shinfo;
	uint16_t buf_len16;
	uint32_t buf_len;
	void *buf;

	if (unlikely(m == NULL))
		return NULL;

	if (rte_pktmbuf_tailroom(m) >= data_len)
		return m;

	buf_len = RTE_PKTMBUF_HEADROOM + data_len;
	buf_len += sizeof(struct rte_mbuf_ext_shared_info) + sizeof(uintptr_t);
	buf_len = RTE_ALIGN_CEIL(buf_len, sizeof(uintptr_t));
	if (unlikely(buf_len > UINT16_MAX))
		goto error;

	buf = rte_malloc(NULL, buf_len, RTE_CACHE_LINE_SIZE);
	if (unlikely(buf == NULL))
		goto error;

	buf_len16 = buf_len;
	shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf, &buf_len16, extbuf_free_cb, buf);
	if (unlikely(shinfo == NULL)) {
		rte_free(buf);
		goto error;
	}

	rte_pktmbuf_attach_extbuf(m, buf, rte_malloc_virt2iova(buf), buf_len16, shinfo);
	rte_pktmbuf_reset_headroom(m);

	return m;

error:
	rte_pktmbuf_free(m);
	return NULL;
}
