# Grout Project Mission

`grout` is a DPDK-based software router that uses the `rte_graph` library for
datapath packet processing. It implements an L3 forwarding stack in userspace.
It is configured over a UNIX socket API and a CLI (`grcli`), and integrates with
FRR for dynamic routing via a dedicated zebra dplane plugin.

This document explains why grout exists, the principles that guide its design,
and how it compares to other approaches to packet forwarding.

## Why grout exists

The Linux kernel networking stack is excellent at terminating connections but
was never designed for high-speed packet forwarding. A single core may forward
around 1 million packets per second with no guarantee against drops -- the
kernel must share CPU time with all other tasks. The overhead comes from
per-packet `sk_buff` allocation (232+ bytes of metadata), system call
transitions, memory copies in the forwarding path (`skb_cow`), interrupt/softirq
context switches, netfilter hook evaluation, qdisc lock contention, and the
generality tax of handling every possible protocol and edge case. A DPDK-based
forwarder like grout achieves upwards of 10 million packets per second per core
on dedicated resources.

DPDK eliminates all of these by running poll-mode drivers in userspace on
dedicated CPU cores, using pre-allocated `rte_mbuf` pools on hugepages and
per-core lockless data structures. The price is steep: the NIC is stolen from
the kernel, standard tools stop working, and you must reimplement the network
stack in userspace.

grout pays that price deliberately. It was born out of a need at Red Hat for
a DPDK-based router to validate OpenStack and OpenShift deployments for telco
use cases. At the time, the only options were `dpdk-testpmd` (a driver test tool
with no networking stack) and proprietary VNFs. grout was created to fill the
gap: a complete, open-source L3 stack built on DPDK, usable both as a test
vehicle and as a production forwarding plane.

## Design philosophy

**Correctness first, performance second.** Get the protocol right, then optimize
the hot path. Optimizations are guided by whole-system profiling rather than
micro-benchmarks of individual functions, and happen when users complain or
business needs surface -- there are no upfront performance targets. The strict
OSI layer separation and clean node boundaries make it easy to profile and
optimize individual nodes without disturbing the rest of the pipeline.

**Simplicity over flexibility.** No serialization framework, no dynamic plugin
loading, no session layer. Each abstraction must earn its place by solving
a concrete problem, not by providing theoretical extensibility.
