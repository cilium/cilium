# Experimental load-balancing control-plane

This package implements a replacement for `ServiceManager` and `ServiceCache`. It aims to simplify
management of the load-balancing state by implementing it as the [StateDB](https://github.com/cilium/statedb) tables services, frontends
and backends. The reconciliation of the state towards BPF maps is implemented asynchronously with the
StateDB reconciler. 

Modifying the state is done via the `Writer` API. It ensures consistency and manages the references between
services, frontends and backends.

The basic architecture looks as follows:
```
  [Data source A]       [Data source B]      [Health checker]    
        \                     |                  /   ^     
         ----------------.    v   .--------------   /
                          [Writer]                 /
                         /    |   \               /
              .---------'     v    '------.      /
         [Services]      [Frontends]    [Backends]
          /                  | ^              |
         /                   v |              v
    [ Observer(s) ]      [Reconciler]    [ Envoy sync ]
                              |
                              v
                          [BPF maps]
```
The different data sources insert data using `Writer.UpsertService`, `Writer.UpsertFrontend`, etc. methods.

The BPF reconciler watches the frontend table (service and backend objects are referenced by
the frontend object) and reconcile updates towards the BPF maps. The reconciliation status is
written back to frontends.

There can be any number of observers to these tables. For example components that need access
to Services can watch the `Table[Service]` instead of e.g. going via `Resource[corev1.Service]`.
For L7 proxying we can sync the backends towards Envoy asynchronously by watching changes to
the backends table.

This architecture enables: 
- Easy addition of new data sources 
- Ability to observe changes to the data at coarse or fine granularity via StateDB watch channels
- Separation of concerns: the error handling is performed by the reconciler and low-level errors are
  not bubbled up to data sources (which wouldn't know how to handle it). Readers are not in the
  critical path.

## Running

The experimental control-plane can be enabled either via the helm option
`loadBalancer.experimental` or via the command-line flag `enable-experimental-lb`. The latter
can be set with cilium-cli: `cilium config set enable-experimental-lb true`.

Enabling the experimental control-plane will swap the `LBMap` instance given to `ServiceManager`
with a fake one. This retains all the agent side functionality except for the updates towards
BPF maps which are instead done by the experimental control-plane.

Once running the state can be inspected with:
```
  $ cilium-dbg shell 
  > db/show frontends
  > db/show backends
  > db/show services
  > db/prefix health agent.controlplane.loadbalancer-experimental
  > lb/maps-dump
```

## Testing

The new architecture makes it easier to write integration tests due to the decoupling. An
integration test for a data source can depend just on the tables & writer and verify that the
tables are correctly populated without having to mock other features or the BPF operations. An
example of this sort of test is in `writer_test.go`.

A more "end-to-end" style test can be found in `script_test.go` that tests going from Kubernetes
objects specified in YAML to the BPF map contents using script tests in `testdata`.

For quick feedback loop you can use the `watch.sh` script to run a script test when the
txtar file changes.

To run the privileged tests:
```
  $ go test -c
  $ PRIVILEGED_TESTS=1 sudo -E ./experimental.test -test.run . -test.v -test.count 1
```
