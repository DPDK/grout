// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Robin Jarry

#include <gr_api.h>
#include <gr_event.h>
#include <gr_iface.h>
#include <gr_infra.h>
#include <gr_log.h>
#include <gr_metrics.h>
#include <gr_module.h>
#include <gr_queue.h>
#include <gr_worker.h>

#include <rte_ethdev.h>
#include <rte_ether.h>

static struct gr_iface *iface_to_api(const struct iface *priv) {
	const struct iface_type *type = iface_type_get(priv->type);
	assert(type != NULL);
	struct gr_iface *pub = malloc(sizeof(*pub) + type->pub_size);
	if (pub == NULL)
		return errno_set_null(ENOMEM);
	pub->base = priv->base;
	memccpy(pub->name, priv->name, 0, sizeof(pub->name));
	type->to_api(pub->info, priv);
	return pub;
}

static struct api_out iface_add(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_add_req *req = request;
	struct gr_infra_iface_add_resp *resp;
	struct iface *iface;

	if (req->iface.id != GR_IFACE_ID_UNDEF)
		return api_out(EINVAL, 0, NULL);

	iface = iface_create(&req->iface, req->iface.info);
	if (iface == NULL)
		return api_out(errno, 0, NULL);

	if ((resp = malloc(sizeof(*resp))) == NULL) {
		iface_destroy(iface);
		return api_out(ENOMEM, 0, NULL);
	}

	resp->iface_id = iface->id;

	return api_out(0, sizeof(*resp), resp);
}

static struct api_out iface_del(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_del_req *req = request;
	struct iface *iface;
	int ret;

	if ((iface = iface_from_id(req->iface_id)) == NULL)
		return api_out(ENODEV, 0, NULL);

	ret = iface_destroy(iface);

	return api_out(-ret, 0, NULL);
}

static struct api_out iface_get(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_get_req *req = request;
	const struct iface_type *type = NULL;
	const struct iface *priv = NULL;
	struct gr_iface *pub = NULL;

	if (req->iface_id != GR_IFACE_ID_UNDEF) {
		if ((priv = iface_from_id(req->iface_id)) == NULL)
			return api_out(ENODEV, 0, NULL);
	} else {
		while ((priv = iface_next(GR_IFACE_TYPE_UNDEF, priv)) != NULL) {
			if (strncmp(priv->name, req->name, sizeof(req->name)) == 0)
				break;
		}
		if (priv == NULL)
			return api_out(ENODEV, 0, NULL);
	}

	type = iface_type_get(priv->type);
	assert(type != NULL);

	pub = iface_to_api(priv);
	if (pub == NULL)
		return api_out(errno, 0, NULL);

	return api_out(0, sizeof(*pub) + type->pub_size, pub);
}

static struct api_out iface_list(const void *request, struct api_ctx *ctx) {
	const struct gr_infra_iface_list_req *req = request;
	const struct iface *iface = NULL;
	int ret = 0;

	while ((iface = iface_next(req->type, iface)) != NULL) {
		const struct iface_type *type = iface_type_get(iface->type);
		struct gr_iface *pub = iface_to_api(iface);
		assert(type != NULL);
		if (pub == NULL) {
			ret = errno;
			goto out;
		}
		api_send(ctx, sizeof(*pub) + type->pub_size, pub);
		free(pub);
	}

out:
	return api_out(ret, 0, NULL);
}

static struct api_out iface_set(const void *request, struct api_ctx *) {
	const struct gr_infra_iface_set_req *req = request;
	int ret;

	ret = iface_reconfig(req->iface.id, req->set_attrs, &req->iface, req->iface.info);
	if (ret < 0)
		return api_out(errno, 0, NULL);

	return api_out(0, 0, NULL);
}

static struct gr_api_handler iface_add_handler = {
	.name = "iface add",
	.request_type = GR_INFRA_IFACE_ADD,
	.callback = iface_add,
};
static struct gr_api_handler iface_del_handler = {
	.name = "iface del",
	.request_type = GR_INFRA_IFACE_DEL,
	.callback = iface_del,
};
static struct gr_api_handler iface_get_handler = {
	.name = "iface get",
	.request_type = GR_INFRA_IFACE_GET,
	.callback = iface_get,
};
static struct gr_api_handler iface_list_handler = {
	.name = "iface list",
	.request_type = GR_INFRA_IFACE_LIST,
	.callback = iface_list,
};
static struct gr_api_handler iface_set_handler = {
	.name = "iface set",
	.request_type = GR_INFRA_IFACE_SET,
	.callback = iface_set,
};

static int iface_event_serialize(const void *obj, void **buf) {
	struct gr_iface *api_iface = iface_to_api(obj);
	if (api_iface == NULL)
		return errno_set(ENOMEM);

	*buf = api_iface;

	const struct iface_type *type = iface_type_get(api_iface->type);
	assert(type != NULL);

	return sizeof(*api_iface) + type->pub_size;
}

static struct gr_event_serializer iface_serializer = {
	.callback = iface_event_serialize,
	.ev_count = 8,
	.ev_types = {
		GR_EVENT_IFACE_ADD,
		GR_EVENT_IFACE_POST_ADD,
		GR_EVENT_IFACE_PRE_REMOVE,
		GR_EVENT_IFACE_REMOVE,
		GR_EVENT_IFACE_POST_RECONFIG,
		GR_EVENT_IFACE_STATUS_UP,
		GR_EVENT_IFACE_STATUS_DOWN,
		GR_EVENT_IFACE_MAC_CHANGE,
	},
};

METRIC_GAUGE(m_up, "iface_up", "Interface administrative state.");
METRIC_GAUGE(m_running, "iface_running", "Interface operational state.");
METRIC_GAUGE(m_mtu, "iface_mtu", "Interface maximum transmission unit.");
METRIC_GAUGE(m_promisc, "iface_promisc", "Interface promiscuous mode.");
METRIC_COUNTER(m_rx_packets, "iface_rx_packets", "Number of received packets.");
METRIC_COUNTER(m_rx_bytes, "iface_rx_bytes", "Number of received bytes.");
METRIC_COUNTER(m_tx_packets, "iface_tx_packets", "Number of transmitted packets.");
METRIC_COUNTER(m_tx_bytes, "iface_tx_bytes", "Number of transmitted bytes.");
METRIC_COUNTER(
	m_cp_rx_packets,
	"iface_cp_rx_packets",
	"Number of packets received by control plane."
);
METRIC_COUNTER(m_cp_rx_bytes, "iface_cp_rx_bytes", "Number of bytes received by control plane.");
METRIC_COUNTER(
	m_cp_tx_packets,
	"iface_cp_tx_packets",
	"Number of packets transmitted by control plane."
);
METRIC_COUNTER(m_cp_tx_bytes, "iface_cp_tx_bytes", "Number of bytes transmitted by control plane.");

static void iface_metrics_collect(struct gr_metrics_writer *w) {
	struct iface *iface = NULL;
	struct gr_metrics_ctx ctx;
	char vrf[16];

	while ((iface = iface_next(GR_IFACE_TYPE_UNDEF, iface)) != NULL) {
		const struct iface_type *type = iface_type_get(iface->type);

		gr_metrics_ctx_init(
			&ctx,
			w,
			"name",
			iface->name,
			"type",
			gr_iface_type_name(iface->type),
			"mode",
			gr_iface_mode_name(iface->mode),
			NULL
		);

		if (iface->mode == GR_IFACE_MODE_VRF) {
			snprintf(vrf, sizeof(vrf), "%u", iface->vrf_id);
			gr_metrics_labels_add(&ctx, "vrf", vrf, NULL);
		} else {
			const struct iface *domain = iface_from_id(iface->domain_id);
			gr_metrics_labels_add(
				&ctx, "domain", domain ? domain->name : "[deleted]", NULL
			);
		}

		gr_metric_emit(&ctx, &m_up, !!(iface->flags & GR_IFACE_F_UP));
		gr_metric_emit(&ctx, &m_running, !!(iface->state & GR_IFACE_S_RUNNING));
		gr_metric_emit(&ctx, &m_mtu, iface->mtu);
		gr_metric_emit(&ctx, &m_promisc, !!(iface->flags & GR_IFACE_F_PROMISC));

		// Aggregate per-core stats
		uint64_t rx_pkts = 0, rx_bytes = 0, tx_pkts = 0, tx_bytes = 0;
		uint64_t cp_rx_pkts = 0, cp_rx_bytes = 0, cp_tx_pkts = 0, cp_tx_bytes = 0;

		for (int i = 0; i < RTE_MAX_LCORE; i++) {
			struct iface_stats *s = iface_get_stats(i, iface->id);
			rx_pkts += s->rx_packets;
			rx_bytes += s->rx_bytes;
			tx_pkts += s->tx_packets;
			tx_bytes += s->tx_bytes;
			cp_rx_pkts += s->cp_rx_packets;
			cp_rx_bytes += s->cp_rx_bytes;
			cp_tx_pkts += s->cp_tx_packets;
			cp_tx_bytes += s->cp_tx_bytes;
		}

		gr_metric_emit(&ctx, &m_rx_packets, rx_pkts);
		gr_metric_emit(&ctx, &m_rx_bytes, rx_bytes);
		gr_metric_emit(&ctx, &m_tx_packets, tx_pkts);
		gr_metric_emit(&ctx, &m_tx_bytes, tx_bytes);
		gr_metric_emit(&ctx, &m_cp_rx_packets, cp_rx_pkts);
		gr_metric_emit(&ctx, &m_cp_rx_bytes, cp_rx_bytes);
		gr_metric_emit(&ctx, &m_cp_tx_packets, cp_tx_pkts);
		gr_metric_emit(&ctx, &m_cp_tx_bytes, cp_tx_bytes);

		// Dispatch to type-specific collector
		if (type->metrics_collect != NULL)
			type->metrics_collect(&ctx, iface);
	}
}

static struct gr_metrics_collector iface_collector = {
	.name = "iface",
	.collect = iface_metrics_collect,
};

RTE_INIT(infra_api_init) {
	gr_register_api_handler(&iface_add_handler);
	gr_register_api_handler(&iface_del_handler);
	gr_register_api_handler(&iface_get_handler);
	gr_register_api_handler(&iface_list_handler);
	gr_register_api_handler(&iface_set_handler);
	gr_event_register_serializer(&iface_serializer);
	gr_metrics_register(&iface_collector);
}
