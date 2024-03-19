# `brouter`: *A sample DPDK router based on rte_graph*

`brouter` stands for *Boring Router*. *Boring* because it should work in all
circumstances, without any fuss nor extended configuration/tuning.

## Better ideas for project names?

| initials | full name       | notes                                            |
|----------|-----------------|--------------------------------------------------|
| tr       | table router    | woodworking joke (clash with `/usr/bin/tr`)      |
| hr       | hand router     | woodworking joke                                 |
| br       | boring router   | boring ssl reference, brouter joke in french     |
| vr       | virtual router  | even more boring than boring router              |
| ur       | micro router    | sounds nice, maybe misleading?                   |
| rr       | routing router  | ends like frr, lion roar joke, makes no sense    |

I lean on the JR acronym for several reasons:

- these are my initials (nobody needs to know).
- `jr` and `jr-cli` are awesome.
- nice reference to [J.R. Ewing](https://fr.wikipedia.org/wiki/J._R._Ewing).

| initials | full name       | notes                                            |
|----------|-----------------|--------------------------------------------------|
| jr       | just (a) router | dinner de cons joke                              |
| jr       | jet router      | short and cute, [PHP project homonym]            |
| jr       | jumbo router    | funnier yet not too extreme, jumbo frames hint   |
| jr       | junk router     | why not?                                         |
| jr       | jump router     | it jumps like a kangaroo                         |

[PHP project homonym]: https://github.com/sformisano/jetrouter

## TODO

- make debug/release target
- write man pages
    * br: command usage
    * br-cli command usage
    * br-api: API to configure the router
- write architecture documentation
- make svg of the projected graph with missing nodes greyed out.

### Control API

- routing table: handle live modification while traffic is running (need patch
  in `rte_fib` to support RCU).

- LATER: select TX (vhost-user)? (dispatch graph mode or special node)

### Dataplane

- Include ARP request/reply handling in the graph.

- QUESTION: adjust mbuf data pointer before enqueue to next graph node?

- LATER: packet classifier node: vector optimization
- LATER: ip lookup node: vector optimization
- LATER: ip rewrite node: vector optimization

## DPDK API GRUDGES

### graph

- TO BE CONFIRMED: Possible issue with `rte_graph_cluster_stats_reset` when
  called from multiple threads on different graphs.

### node

- ideally, we would need a generic way to pass node context data agnostic of
  the control plane implementation. Maybe using a global `rte_hash` with
  a well-known name that can be referenced from the node init callbacks.

- node context data is a 16 bytes array. When storing pointers (2 pointers max)
  it requires obscure casting that is error prone.

- `rx`: tightly coupled with graph layout generation (multiple rx/tx nodes on
  a single graph).

- `ethdev_tx`: TX queue id is initialized to `graph_id` ???

- `ip_lookup`: global LPM variable, no way to do dynamic reconfig. No way to
  use fib.

- `ip_rewrite`: high complexity due to multiple TX nodes per graph (also not
  flexible with other graph layouts).

- `classify`: add generic api without hard coded next nodes.

### fib

- every ipv4 address (route *and* next hop) needs to be host order (why not
  hiding this in the API)

- no api to list all configured routes

- is it ok to modify the fib while performing lookups in parallel?

- missing neon vector code for DIR24 and TRIE.
