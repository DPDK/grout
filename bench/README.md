# RFC 2544 performance tests

This directory holds self-contained performance test scenarios for grout. Each
scenario is a pair of files sharing the same base name:

- `<test>.grcli` - grout configuration, applied on top of a partially configured
  daemon with `grcli -xef bench/<test>.grcli`.

- `<test>.py` - a [TRex](https://trex-tgen.cisco.com/) stateless traffic profile
  describing the packets sent in each direction. It is a Python module. The
  harness loads it as a TRex profile.

They are meant to be driven by an external test harness which discovers the
scenarios, configures grout, loads the matching TRex profile and runs
a bidirectional NDR/PDR binary search (RFC 2544 throughput). The scenario files
carry no traffic generator of their own; they fully describe what grout and TRex
must do. A small local validation helper lives under `harness/` (see below) for
smoke-testing a scenario without TRex.

## Topology

Both files assume a fixed, symmetric back-to-back topology set up by the
harness:

    .---------------.                      .---------------.
    |               |                      |               |
    |           p0 -------------------------- port0        |
    |  grout        |                      |         TRex  |
    |           p1 -------------------------- port1        |
    |               |                      |               |
    '---------------'                      '---------------'

- grout has exactly two physical ports named `p0` and `p1`.
- TRex port 0 is cabled (directly or through a top-of-rack switch) to grout
  `p0`, TRex port 1 to grout `p1`.
- In the traffic profiles, **direction 0** means "TRex port 0 -> grout p0" and
  **direction 1** means "TRex port 1 -> grout p1".

## What the harness must do before running a `.grcli`

The `.grcli` files start from a grout that is **already partially configured**:

1. CPU affinity is set (`affinity cpus set control ... datapath ...`).

2. The two physical ports `p0` and `p1` exist, created with the desired number
   of RX queues and queue size, e.g.:

   ```
   interface add port p0 devargs <pci0> rxqs <n> qsize <q>
   interface add port p1 devargs <pci1> rxqs <n> qsize <q>
   ```

Everything else (port MAC addresses, L3 addresses, nexthops, routes, tunnels,
bridges...) is set by the `.grcli` file itself. This keeps the affinity and port
sizing (the machine-specific and performance-sensitive part) under the harness's
control, while the scenario logic stays in this repository.

## No dynamic resolution: hardcoded MAC addresses everywhere

The scenarios must run **without FRR and without ARP/NDP**. All next hops are
static and every MAC address is hardcoded:

- The `.grcli` file sets a deterministic MAC on each grout port (`interface set
  port pN mac ...`) and puts the same hardcoded MAC in every next hop (`nexthop
  add l3 ... mac ...`).

- The `.py` traffic profile builds every frame with an explicit `Ether(src=...,
  dst=...)`.

This makes the tests independent of the physical NIC MAC addresses of both grout
and TRex, and keeps any top-of-rack switch between them from getting confused:
the switch always sees the same stable set of source MACs and forwards
accordingly. TRex runs in promiscuous mode, so it accepts whatever comes back.

Because grout rewrites the Ethernet source address of forwarded frames to the
egress port MAC, and only routes frames whose destination MAC matches the
ingress interface MAC, the convention is:

- TRex sends frames **to** the grout port MAC and **from** the TRex-side MAC.
- grout next hops point **to** the TRex-side MAC.

### Address plan

All scenarios reuse the same address and MAC plan (mirroring the `smoke/` tests).
Deviations are documented inline in each file.

| Role                           | Value                           |
|--------------------------------|---------------------------------|
| grout `p0` MAC                 | `02:00:00:00:00:00`             |
| grout `p1` MAC                 | `02:00:00:00:00:01`             |
| TRex port 0 MAC (p0 nexthop)   | `02:00:00:00:01:00`             |
| TRex port 1 MAC (p1 nexthop)   | `02:00:00:00:01:01`             |
| grout `p0` address (IPv4)      | `172.16.0.1/24`                 |
| grout `p1` address (IPv4)      | `172.16.1.1/24`                 |
| TRex `p0` nexthop (IPv4)       | `172.16.0.2`                    |
| TRex `p1` nexthop (IPv4)       | `172.16.1.2`                    |
| grout `p0` address (IPv6)      | `fd00:0::1/64`                  |
| grout `p1` address (IPv6)      | `fd00:1::1/64`                  |
| TRex `p0` nexthop (IPv6)       | `fd00:0::2`                     |
| TRex `p1` nexthop (IPv6)       | `fd00:1::2`                     |
| Subnet reachable behind `p0`   | `16.0.0.0/16`, `fd00:100::/64`  |
| Subnet reachable behind `p1`   | `48.0.0.0/16`, `fd00:200::/64`  |

So a "p0 -> p1" flow is `16.0.0.0/16 -> 48.0.0.0/16` (IPv4) or `fd00:100::/64 ->
fd00:200::/64` (IPv6), and vice versa.

## The `# name:` convention

For discovery, both files of a scenario carry a human-readable name in
a comment:

```sh
# name: IPv4 forwarding
```

The line matches the regular expression `^#\s*name:\s*(.+)$`. Both grout batch
files (via the libecoli shell lexer) and Python treat `#` as a line comment, so
the same convention works in both. A harness can list the scenarios by globbing
`bench/*.grcli` and reading the name from either file of the pair.

## Frame sizes

Plain (non-tunneled) directions send 64-byte frames (60 bytes on the wire plus
the 4-byte FCS added by the NIC), the RFC 2544 minimum. Directions that add
encapsulation (SRv6, VXLAN) produce larger frames; the profile pads only the
plain side up to 64 bytes and lets the encapsulated side keep its natural size.
Each profile documents its own sizes.

## Flow spreading

Every profile attaches an `STLVM` that sweeps a source UDP port (`1024-65535`)
so the traffic is made of many flows and spreads over the receive queues instead
of hammering a single one. The source UDP port is varied rather than the source
IP address on purpose: rewriting the IP would force an L3 checksum
recomputation, while the customer UDP port can be rewritten freely (its checksum
is left at 0, which is valid for the forwarded IPv4 payloads).

For the VXLAN scenarios the swept port differs per direction. In the decap
direction the *outer* VXLAN UDP source port is swept - that is the RSS key on
grout's receive side (its ports hash UDP), so it must vary to spread the
encapsulated traffic across the receive queues - and the outer UDP checksum is
recomputed in hardware (`fix_chksum_hw`) so the swept port keeps a valid
checksum. grout verifies the outer UDP checksum on decap (mandatory over IPv6,
where a zero checksum is invalid). In the encap direction the customer UDP
source port is swept: grout derives the outer VXLAN source port from the inner
flow hash (`vxlan_src_port(m->hash.rss)`), so varying the customer flow spreads
the encapsulated traffic it emits.

## Trying the scenarios locally (dummy harness)

`harness/` contains a dev-only harness that emulates the external element on
a single machine so a scenario can be smoke-tested end to end without TRex. It
starts grout in test mode, creates `p0`/`p1` as tap interfaces (the external
element: startup affinity + ports), applies `<test>.grcli`, then loads
`<test>.py` against a mock `trex_stl_lib` to build the packets, injects them on
the ingress tap with scapy and checks a frame comes out the expected egress tap
(both directions).

It needs root - `unshare`, tap creation and `AF_PACKET` all require
`CAP_NET_ADMIN`, like `make smoke-tests` - and scapy on the host.

```sh
make                                   # build grout + grcli into build/
sudo bench/harness/validate.sh ipv4    # one scenario
make bench-validate                    # validate all scenarios
```

Each run reports, per direction, how many frames were sent and forwarded and
prints a summary of the egress frame. This is a forwarding-sanity check (a frame
reaches the right egress port), not a full validation of the encap/decap/rewrite.

## Adding a new scenario

1. Copy `example.grcli.template` to `<test>.grcli` and `example.py.template` to
   `<test>.py`.

2. Set the same `# name: ...` in both files. Strip down the template comments.

3. Fill in the grout configuration and the TRex streams, reusing the address
   plan above. Keep both files self-contained (no shared imports): a harness
   must be able to copy the pair anywhere and run it.

4. Add relevant introduction comments for this new test.

5. Validate the grout side against the daemon: `grcli -xef bench/<test>.grcli`
   (with `p0`/`p1` already created).
