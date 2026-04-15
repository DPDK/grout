// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2024 Christophe Fontaine

#include "cli.h"
#include "cli_event.h"

#include <gr_api.h>
#include <gr_infra.h>
#include <gr_net_types.h>

#include <signal.h>
#include <string.h>
#include <sys/queue.h>

static STAILQ_HEAD(, cli_event_printer) printers = STAILQ_HEAD_INITIALIZER(printers);

void cli_event_printer_register(struct cli_event_printer *p) {
	STAILQ_INSERT_TAIL(&printers, p, next);
}

static const struct cli_event_printer *get_event_printer(uint32_t ev_type) {
	const struct cli_event_printer *p;
	STAILQ_FOREACH (p, &printers, next) {
		for (unsigned i = 0; i < p->ev_count; i++)
			if (p->ev_types[i] == ev_type)
				return p;
	}
	return NULL;
}

static volatile sig_atomic_t stop;

static void sighandler(int) {
	stop = true;
}

static cmd_status_t events_show(struct gr_api_client *c, const struct ec_pnode *p) {
	struct gr_event_subscribe_req req = {.suppress_self_events = false};
	const struct cli_event_printer *printer;
	cmd_status_t status = CMD_ERROR;
	struct gr_api_event *e = NULL;
	uint64_t max_count = 0;
	uint64_t count = 0;
	int ret;

	if (arg_u64(p, "COUNT", &max_count) < 0 && errno != ENOENT)
		return CMD_ERROR;

	if (ec_pnode_find(p, "TYPE") != NULL) {
		const struct ec_pnode *t = NULL;
		while ((t = ec_pnode_find_next(p, t, "TYPE", false)) != NULL) {
			const struct ec_strvec *v = ec_pnode_get_strvec(t);
			assert(v != NULL);
			assert(ec_strvec_len(v) == 1);
			const char *type = ec_strvec_val(v, 0);

			STAILQ_FOREACH (printer, &printers, next)
				if (strcmp(printer->name, type) == 0)
					break;
			if (printer == NULL) {
				errno = EINVAL;
				goto out;
			}
			for (unsigned i = 0; i < printer->ev_count; i++) {
				req.ev_type = printer->ev_types[i];
				ret = gr_api_client_send_recv(
					c, GR_EVENT_SUBSCRIBE, sizeof(req), &req, NULL
				);
				if (ret < 0)
					goto out;
			}
		}
	} else {
		req.ev_type = GR_EVENT_ALL;
		if (gr_api_client_send_recv(c, GR_EVENT_SUBSCRIBE, sizeof(req), &req, NULL) < 0)
			return CMD_ERROR;
	}

	struct sigaction sa = {.sa_handler = sighandler};
	struct sigaction old_int, old_term, old_pipe;
	sigaction(SIGINT, &sa, &old_int);
	sigaction(SIGTERM, &sa, &old_term);
	sigaction(SIGPIPE, &sa, &old_pipe);

	stop = false;
	while (!stop && gr_api_client_event_recv(c, &e) == 0) {
		printf("> ");

		printer = get_event_printer(e->ev_type);
		if (printer != NULL)
			printer->print(e->ev_type, PAYLOAD(e));
		else
			printf("unknown event 0x%08x\n", e->ev_type);

		free(e);
		count++;
		if (max_count != 0 && count >= max_count)
			break;
	}

	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
	sigaction(SIGPIPE, &old_pipe, NULL);
	status = CMD_SUCCESS;
	errno = 0;
out:
	ret = errno;
	gr_api_client_send_recv(c, GR_EVENT_UNSUBSCRIBE, 0, NULL, NULL);
	errno = ret;
	return status;
}

static int complete_event_names(
	struct gr_api_client *,
	const struct ec_node *node,
	struct ec_comp *comp,
	const char *arg,
	void * /*cb_arg*/
) {
	const struct cli_event_printer *p;
	int ret = 0;

	STAILQ_FOREACH (p, &printers, next) {
		if (ec_str_startswith(p->name, arg)) {
			if (!ec_comp_add_item(comp, node, EC_COMP_FULL, arg, p->name))
				ret = -1;
		}
	}

	return ret;
}

static int ctx_init(struct ec_node *root) {
	return CLI_COMMAND(
		CLI_CONTEXT(root, CTX_ARG("events", "Grout events")),
		"[show] [(count COUNT),(type TYPE)+]",
		events_show,
		"Subscribe to grout events and dump them in real time",
		with_help(
			"Stop printing events after COUNT.",
			ec_node_uint("COUNT", 1, UINT32_MAX, 10)
		),
		with_help(
			"Event type to subscribe to.",
			ec_node_dyn("TYPE", complete_event_names, NULL)
		)
	);
}

static struct cli_context ctx = {
	.name = "events",
	.init = ctx_init,
};

static void __attribute__((constructor, used)) init(void) {
	cli_context_register(&ctx);
}
