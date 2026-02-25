// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Christophe Fontaine

#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>

#include <rte_bpf.h>
#include <rte_malloc.h>

#include <pcap.h>
#include <string.h>

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
