// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include <gr_api.h>
#include <gr_cli.h>
#include <gr_cli_event.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <sys/queue.h>

static STAILQ_HEAD(, gr_cli_event_printer) printers = STAILQ_HEAD_INITIALIZER(printers);

void gr_cli_event_register_printer(struct gr_cli_event_printer *p) {
	STAILQ_INSERT_TAIL(&printers, p, next);
}

static const struct gr_cli_event_printer *get_event_printer(uint32_t ev_type) {
	const struct gr_cli_event_printer *p;
	STAILQ_FOREACH (p, &printers, next) {
		for (unsigned i = 0; i < p->ev_count; i++)
			if (p->ev_types[i] == ev_type)
				return p;
	}
	return NULL;
}

static cmd_status_t events_show(struct gr_api_client *c, const struct ec_pnode *) {
	struct gr_event_subscribe_req req = {
		.suppress_self_events = false, .ev_type = EVENT_TYPE_ALL
	};
	const struct gr_cli_event_printer *p;
	struct gr_api_event *e = NULL;

	if (gr_api_client_send_recv(c, GR_MAIN_EVENT_SUBSCRIBE, sizeof(req), &req, NULL) < 0)
		return CMD_ERROR;

	while (gr_api_client_event_recv(c, &e) == 0) {
		printf("> ");

		p = get_event_printer(e->ev_type);
		if (p != NULL)
			p->print(e->ev_type, PAYLOAD(e));
		else
			printf("unknown event 0x%08x\n", e->ev_type);

		free(e);
	}

	gr_api_client_send_recv(c, GR_MAIN_EVENT_UNSUBSCRIBE, 0, NULL, NULL);

	return 0;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(
		CLI_CONTEXT(root, CTX_SHOW),
		"events",
		events_show,
		"Subscribe to all events and dump them in real time"
	);
}

static struct gr_cli_context ctx = {
	.name = "events",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	register_context(&ctx);
}
