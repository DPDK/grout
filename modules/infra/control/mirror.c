// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include <gr_api.h>
#include <gr_control_queue.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_mirror.h>
#include <gr_version.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_mempool.h>
#include <gr_module.h>
#include <gr_port.h>
#include <gr_vlan.h>

#include <rte_bpf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_pcapng.h>

#include <fcntl.h>
#include <pcap.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#define MIRROR_PCAPNG_POOL "mirror_pcapng_pool"
#define MIRROR_PCAPNG_POOL_SIZE (RTE_GRAPH_BURST_SIZE * 4)

static rte_pcapng_t *mirror_pcapng;
static struct rte_mempool *mirror_pcapng_mp;
static atomic_bool mirror_pcapng_enabled = false;

void mirror_pcapng_cb(void *obj, uintptr_t, const struct control_queue_drain *drain) {
	struct rte_mbuf *m = obj;
	struct mbuf_data *d = mbuf_data(m);

	if (drain != NULL && drain->event == GR_EVENT_IFACE_REMOVE && d->iface == drain->obj)
		goto free_mbuf;

	if (!atomic_load(&mirror_pcapng_enabled) || mirror_pcapng == NULL
	    || mirror_pcapng_mp == NULL)
		goto free_mbuf;

	ssize_t written = rte_pcapng_write_packets(mirror_pcapng, &m, 1);
	if (written < 0)
		LOG(ERR, "mirror pcapng write: %s", rte_strerror(rte_errno));

free_mbuf:
	rte_pktmbuf_free(m);
}

bool mirror_pcapng_enabled_get(void) {
	return atomic_load(&mirror_pcapng_enabled);
}

static int mirror_pcapng_open(const char *path) {
	int fd;

	if (mirror_pcapng != NULL)
		return 0;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return errno_set(errno);

	mirror_pcapng = rte_pcapng_fdopen(fd, NULL, NULL, GROUT_VERSION, NULL);
	if (mirror_pcapng == NULL) {
		close(fd);
		return errno_set(rte_errno);
	}

	return 0;
}

static void mirror_pcapng_close(void) {
}

int mirror_pcapng_enable(const char *path) {
	int ret;

	if (path == NULL || path[0] == '\0')
		return errno_set(EINVAL);

	ret = mirror_pcapng_open(path);
	if (ret < 0)
		return ret;

	atomic_store(&mirror_pcapng_enabled, true);
	return 0;
}

void mirror_pcapng_disable(void) {
	atomic_store(&mirror_pcapng_enabled, false);
	mirror_pcapng_close();
}

static void mirror_module_fini(struct event_base *) {
	mirror_pcapng_disable();
}

static struct gr_module mirror_module = {
	.name = "mirror",
	.depends_on = "graph",
	.fini = mirror_module_fini,
};

static struct api_out mirror_capture_set(const void *request, struct api_ctx *) {
	const struct gr_mirror_capture_set_req *req = request;

	if (req->enabled) {
		if (req->path[0] == '\0')
			return api_out(EINVAL, 0, NULL);
		if (mirror_pcapng_enable(req->path) < 0)
			return api_out(errno, 0, NULL);
	} else {
		mirror_pcapng_disable();
	}
	return api_out(0, 0, NULL);
}

RTE_INIT(mirror_constructor) {
	gr_register_module(&mirror_module);
	gr_api_handler(GR_MIRROR_CAPTURE_SET, mirror_capture_set);
}

int iface_mirror_filter_compile(const char *expr, struct rte_bpf **out) {
	struct bpf_program fcode;
	struct rte_bpf_prm *prm;
	struct rte_bpf *bpf;
	pcap_t *pcap;

	*out = NULL;

	if (expr == NULL || expr[0] == '\0')
		return 0;

	pcap = pcap_open_dead(DLT_EN10MB, 262144);
	if (pcap == NULL) {
		LOG(ERR, "pcap_open_dead failed");
		return errno_set(EINVAL);
	}

	if (pcap_compile(pcap, &fcode, expr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
		LOG(ERR, "mirror filter \"%s\": %s", expr, pcap_geterr(pcap));
		pcap_close(pcap);
		return errno_set(EINVAL);
	}

	prm = rte_bpf_convert(&fcode);
	pcap_freecode(&fcode);
	pcap_close(pcap);

	if (prm == NULL) {
		LOG(ERR, "rte_bpf_convert \"%s\": %s", expr, rte_strerror(rte_errno));
		return -rte_errno;
	}

	bpf = rte_bpf_load(prm);
	rte_free(prm);

	if (bpf == NULL) {
		LOG(ERR, "rte_bpf_load \"%s\": %s", expr, rte_strerror(rte_errno));
		return -rte_errno;
	}

	*out = bpf;
	return 0;
}

void iface_mirror_filter_destroy(struct rte_bpf *bpf) {
	if (bpf != NULL)
		rte_bpf_destroy(bpf);
}
