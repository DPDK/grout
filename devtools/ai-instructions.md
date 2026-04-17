# grout - AI Instructions

grout (Graph Router) is a DPDK-based network processing application. It uses
the `rte_graph` library for datapath processing. It simulates network functions
or physical routers using an opensource stack. It is configured over a UNIX
socket via a client library and a CLI (`grcli`).

## Build System

The project uses meson with a GNUmakefile wrapper. Key make targets:

- `make` — build the project
- `make unit-tests` — run unit tests (meson test)
- `make smoke-tests` — run integration tests (requires sudo access, can run
  parallel tests with `make -j8 smoke-tests`)
- `make lint` — run clang-format, license checks, white space checks, codespell
- `make format` — auto-format C code with clang-format
- `make check-patches` — validate commit messages
- `sudo smoke/foo_test.sh build` - run a single integration test with full
  debugging traces

## Top-Level Structure

- `main/` — grout daemon: main loop, DPDK init, module loader, API server,
  metrics, signal handling, systemd integration.
- `cli/` — `grcli` CLI client: interactive shell, command execution, ecoli
  integration, tab completion.
- `api/` — shared headers between daemon and clients: API protocol, type
  definitions, utility functions.
- `modules/` — packet processing modules (see below).
- `frr/` — FRR zebra dplane plugin (GPL-2.0-or-later): synchronizes grout
  routes/interfaces with FRR routing daemons.
- `smoke/` — integration test scripts (shell scripts run with `make smoke`).
- `devtools/` — development helper scripts (commit checks, etc.).
- `docs/` — documentation and graph images.
- `subprojects/` — meson subprojects: `dpdk/` (DPDK) and `ecoli/` (libecoli
  for CLI parsing).

## Modules

- `modules/infra/` — interface management, nexthops, ports, VRFs, workers
  and datapath main loop
- `modules/ip/` — IPv4 forwarding
- `modules/ip6/` — IPv6 forwarding
- `modules/ipip/` — IP-in-IP tunnels (simple module, no subdirectories)
- `modules/l2/` — L2 bridging
- `modules/l4/` — L4 input/loopback processing, OSPF redirect (simple module)
- `modules/dhcp/` — DHCP client
- `modules/policy/` — NAT: stateless DNAT44, stateful SNAT44 with conntrack
- `modules/srv6/` — SRv6 support

## Module Structure

Each module should have 4 sub-directories (except very simple ones like `ipip`
and `l4` which use flat files).

- `api/` — exported API headers to clients and API handlers.
- `cli/` — `grcli` commands for related API endpoints.
- `control/` — control plane code, sometimes API handlers can be stored here.
- `datapath/` — datapath nodes.

## API Architecture

Each module defines request types as `REQUEST_TYPE(MODULE_ID, req_id)` in its
`api/gr_*.h` header along with request/response structs. Handlers have the
signature `struct api_out cb(const void *request, struct api_ctx *)` and are
registered at init time via `RTE_INIT()` calling `gr_register_api_handler()`.
The server (`main/api.c`) dispatches requests over a UNIX socket using
libevent. Clients use `gr_api_client_send_recv()` for simple request/response,
or `gr_api_client_stream_foreach()` for list operations (multiple responses
terminated by an empty payload). There is also an event subscription system
for async notifications.

## Datapath Workers and Graph Nodes

Each worker is a thread pinned to a CPU core, running an `rte_graph` in a tight
loop (`modules/infra/datapath/main_loop.c`). One `port_rx` and `port_tx` node
clone is created per port/queue pair (e.g. `port_rx-p0q1`, `port_tx-p2q0`).
Each worker's graph only includes the RX clones for its assigned queues, but
all TX clones are included in every graph. The `port_output` node steers
packets to the right `port_tx-pXqY` clone.

On config changes, `worker_graph_reload_all()` does a two-phase swap: first
stop all workers (set their graph to NULL via atomic config swap), then create
new graphs with updated queue assignments and signal workers to pick them up.
Each worker has two graph slots (`graph[0]`/`graph[1]`) for lock-free swapping.
Node clones no longer used in any graph are freed after all graphs are rebuilt.
The datapath checks for config changes every 256 graph walks via atomic loads
(no locks in the hot path).

## BASE() Macro

The `BASE(typename)` macro creates an anonymous union allowing a struct to
embed another and access its fields directly. Used throughout the codebase
for type-specific extensions (interfaces, nexthops, etc.).

## Interface Updates

Interface modification API requests use `set_attrs` bitmasks to control
which fields are updated — only flagged fields are modified.

## CLI Command Registration

CLI uses libecoli for parsing. Commands are registered with the
`CLI_COMMAND(ctx, syntax, callback, help)` macro which uses
`__attribute__((constructor))` for auto-registration. Callbacks receive
a `struct gr_api_client *` and the ecoli parse node to extract arguments.
Contexts nest via `CLI_CONTEXT()` to build hierarchical command trees.

## Module Initialization

Modules register via `module_register()` with a `depends_on` string
(comma-separated, supports fnmatch patterns). They are topologically sorted
at startup; circular or missing dependencies cause ABORT. Each module has
`init`/`fini` callbacks called in dependency/reverse order.

## RCU

The datapath uses DPDK's QSBR (quiescent state based reclamation) model.
Workers call `rte_rcu_qsbr_quiescent()` periodically in the main loop. The
control plane calls `rte_rcu_qsbr_synchronize()` before freeing shared data.
DPDK hash tables used with `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` are
attached to this RCU via `rte_hash_rcu_qsbr_add()`.

## Error Handling

Use `errno_set(err)` to return `-err` with errno set, or `errno_log(err, msg)`
to also log. API handlers return `api_out(status, len, payload)` where status
is 0 or an errno value. Response payloads are allocated by the handler and
freed by the framework.

## Important Implementation Details

- Make minimal changes. Only modify what is strictly necessary.
- Ask before making significant changes or when multiple approaches exist.
- Avoid unnecessary refactoring, cleanup, or "improvements" beyond the request.
- Do not add comments, docstrings, or type annotations to unchanged code.
- Preserve existing comments unless they no longer apply or are invalid.
- Memory allocated with `rte_*alloc*()` functions must be freed with
  `rte_free()`.
- Arrays managed with `arr_add()` must be freed with `arr_free()`.
- `arr_free(x)` sets `x = NULL`, no risk of double free.
- `rte_*` symbols are from DPDK (`subprojects/dpdk/`).
- `ec_*` symbols are from libecoli (`subprojects/ecoli/`).
- **NEVER** invoke any system call, printf or the `LOG()` macro in datapath
  code.

## Code Style & Conventions

See @.editorconfig for indentation and line length limits. See @CONTRIBUTING.md
for C coding style.

## Git Commit Guidelines

**IMPORTANT:** Always run git commands from the repository root directory.
NEVER use `git -C /path`. Change to the correct directory first if needed.

See @CONTRIBUTING.md for expected commit message format and git trailers.

- **Title:** Use component-based prefix (e.g., `ip:`, `cli:`, `infra:`) followed
  by all lowercase title except for acronyms/symbols.
- **Use imperative mood:** "add feature" not "added feature"
- **Hard wrap body to 72 columns**
- **Sign-off required:** Use `git commit --signoff`
- **One issue per commit**
- **Emojis are forbidden:** Use regular UTF-8 printable characters.
- **Avoid bullet lists unless necessary:** Prefer regular prose
- **Do not paraphrase the diff:** No need to repeat what files were added,
  modified or changed. Only mention added functions or symbols when this is
  relevant in the context of the commit.
- **Avoid shallow/empty statements:** We don't need AI slop. We need actual
  information that is not present in the diff already.
- **Commit body is NOT optional**
- **Write like a human:** use plain, straightforward language; no fancy
  words or convoluted phrasing that screams "AI-generated"
- **Keep commit bodies short:** a couple of sentences is usually enough;
  only write more when the change is genuinely complex

Here is a pathological example:

```
🚀 Restructure core components for better scalability

The following modifications were performed to ensure improved scalability and maintainability:

- Refactored code to follow best practices
- Reorganized files to make the structure cleaner
- Simplified logic in some areas for easier understanding
- Prepared the codebase for future features and improvements

This refactor sets the stage for a more robust architecture.

The following files were modified:

- modules/infra/control/gr_port.h
- modules/infra/control/iface.c
- modules/infra/control/nexthop.c
- modules/infra/control/port.c

Assisted-by: Lame AI v2
Signed-off-by: Foo Bar <foo@bar.com>
```

Here is a good example:

```
rx,tx: use one node per port queue

Instead of dealing with a list of queues to poll packets from,
instantiate one port_rx node clone for each configured port RX queue.

Do the same thing for port_tx and each configured port TX queue.

Depending on worker RX queue mapping, include the associated
port_rx-p*q* clones and initialize their context data accordingly.

Always include *all* port_tx-p*q* clones in all graphs, regardless of
worker TX queue mappings. Instead, configure the port_output node
context to steer packets to the proper port_tx-p*q* clone.

All of this requires delicate juggling with multiple node names lists to
ensure that nodes are cloned when needed before they are affected to
a graph. Secondly, we need to call rte_node_free() on those which are
not used in any graph after all of them have been reloaded.

Signed-off-by: Foo Bar <foo@bar.com>
```
