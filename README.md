# BRouter: A Boring Router

## TODO

### Control API

- graph statistics
- routing table: handle live modification while traffic is running
- worker management

### Dataplane

- proper CPU pinning
- packet classifier node: vector optimization
- ip lookup node: vector optimization
- ip rewrite node: vector optimization

## DPDK API GRUDGES

### graph dynamic reconfig

- no way to pass node context data with `rte_graph_create`
- need to generate unique node names manually
- no way to free nodes after they have been created

### node

- `ethdev_tx`: tx queue id is initialized to `graph_id` ???
- `ip_lookup`: global lpm variable, no way to do dynamic reconfig

### fib

- every ipv4 address (route *and* next hop) needs to be host order (why not
  hiding this in the API)
- no api to list all configured routes
