// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "loopback.h"

#include <gr_graph.h>
#include <gr_infra.h>
#include <gr_ip4_datapath.h>
#include <gr_ip6_datapath.h>
#include <gr_log.h>
#include <gr_loopback.h>
#include <gr_trace.h>

#include <rte_malloc.h>

#include <linux/if_tun.h>
#include <sys/uio.h>

static uint16_t
loopback_output_process(struct rte_graph *, struct rte_node *, void **objs, uint16_t nb_objs) {
	struct iface_info_loopback *lo;
	struct iovec iov[2];
	struct mbuf_data *d;
	struct rte_mbuf *m;
	struct tun_pi pi;
	char *data;

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = mbuf_data(m);

		lo = (struct iface_info_loopback *)d->iface->info;
		if (rte_pktmbuf_linearize(m) == 0) {
			data = rte_pktmbuf_mtod(m, char *);
		} else {
			data = rte_malloc(NULL, rte_pktmbuf_pkt_len(m), 0);
			if (data == NULL) {
				LOG(ERR, "rte_malloc failed %s", rte_strerror(rte_errno));
				goto next;
			}
			// with a non-contiguous mbuf, rte_pktmbuf_read returns a pointer
			// to the user provided buffer.
			rte_pktmbuf_read(m, 0, rte_pktmbuf_pkt_len(m), data);
		}
		pi.flags = 0;
		if ((data[0] & 0xf0) == 0x40)
			pi.proto = RTE_BE16(RTE_ETHER_TYPE_IPV4);
		else if ((data[0] & 0xf0) == 0x60)
			pi.proto = RTE_BE16(RTE_ETHER_TYPE_IPV6);
		else {
			LOG(ERR, "Bad proto: 0x%x - drop packet", data[0]);
			goto next;
		}
		// Do not retry even in case of  if EAGAIN || EWOULDBLOCK
		// If the tun device queue is full, something really bad is
		// already happening on the management plane side.
		iov[0].iov_base = &pi;
		iov[0].iov_len = sizeof(pi);
		iov[1].iov_base = data;
		iov[1].iov_len = rte_pktmbuf_pkt_len(m);

		if (writev(lo->fd, iov, ARRAY_DIM(iov)) < 0) {
			// The user messed up and removed gr-loopX
			// release resources on our side to try to recover
			if (errno == EBADFD) {
				iface_destroy(d->iface->id);
			}
			LOG(ERR, "write to tun device failed %s", strerror(errno));
		}

next:
		if (!rte_pktmbuf_is_contiguous(m))
			rte_free(data);
		rte_pktmbuf_free(m);
	}
	return nb_objs;
}

static struct rte_node_register loopback_output_node = {
	.name = "loopback_output",
	.process = loopback_output_process,
	.nb_edges = 0,
	.next_nodes = {},
};

static void loopback_output_register(void) {
	ip_output_register_interface_type(GR_IFACE_TYPE_LOOPBACK, "loopback_output");
	ip6_output_register_interface_type(GR_IFACE_TYPE_LOOPBACK, "loopback_output");
}

static struct gr_node_info info = {
	.node = &loopback_output_node,
	.register_callback = loopback_output_register,
};

GR_NODE_REGISTER(info);
