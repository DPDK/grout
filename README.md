# BRouter: A Boring Router

## TODO

### Control API

- graph statistics
- routing table: handle live modification while traffic is running
- register system for nodes to plug themselves into the graph DONE'ish
- select TX (vhost-user)? (dispatch graph mode or special node)

### Dataplane

- packet classifier node: vector optimization
- ip lookup node: vector optimization
- ip rewrite node: vector optimization

## DPDK API GRUDGES

### node

- ideally, we would need a generic way to pass node context data agnostic of
  the control plane implementation. Maybe using a global rte_hash with
  a well-known name that can be referenced from the node init callbacks.
- node context data is a 16 bytes array. When storing pointers (2 pointers max)
  it requires obscure casting that is error prone.
- `rx`: tightly coupled with graph layout generation (multiple rx/tx nodes on
  a single graph).
- `ethdev_tx`: tx queue id is initialized to `graph_id` ???
- `ip_lookup`: global lpm variable, no way to do dynamic reconfig. No way to
  use fib.
- `ip_rewrite`: high complexity due to multiple tx nodes per graph (also not
  flexible with other graph layouts).
- `classify`: add generic api without hard coded next nodes.

### fib

- every ipv4 address (route *and* next hop) needs to be host order (why not
  hiding this in the API)
- no api to list all configured routes
- is it ok to modify the fib while performing lookups in parallel?
- missing neon vector code for dir24 and trie.
