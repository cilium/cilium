# Load-balancing control-plane

This package implements the core load-balancing control-plane. Built on top of
[StateDB](https://github.com/cilium/statedb) around 3 core tables:
- `Table[*Frontend]` (frontends): Service frontends keyed by address, port and protocol.
  The frontend references backends associated with it. Frontends are what are reconciled
  to BPF maps.
- `Table[*Service]` (services): Service metadata shared by multiple frontends.
- `Table[*Backend]` (backends): Backends associated with services.

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
                             | ^              |
                             v |              v
                         [Reconciler]    [ L7 proxy (Envoy) ]
                              |
                              v
                          [BPF maps]
```

The different data sources insert data using `Writer.UpsertService`, `Writer.UpsertFrontend`, etc. methods.

The main data source is of course the Kubernetes one which is implemented in `reflector.go`. It batches up
changes to Services and EndpointSlices and commits them periodically so the system can process changes in
batches. Kubernetes Services are mapped to a Service object with zero or more Frontends. From EndpointSlices
a Backend instance is created. Each Backend object contains a set of instances, one per service that references
it.

The BPF reconciler (bpf_reconciler.go) watches the frontend table (service and backend objects
are referenced by the frontend object) and reconcile updates towards the BPF maps. The reconciliation status is
written back to frontends (`Status` field).

This architecture enables: 
- Easy addition of new data sources 
- Ability to observe changes to the data at coarse or fine granularity via StateDB watch channels
- Separation of concerns: the error handling is performed by the reconciler and low-level errors are
  not bubbled up to data sources (which wouldn't know how to handle it). Readers are not in the
  critical path.

## Source code organization

The core source files are:

- service.go, frontend.go, backend.go: The struct and table definitions
- config.go: Configuration structs. `Config` is the main configuration, `ExtConfig` bridges from
  `option.DaemonConfig` to avoid direct references to it (to be removed eventually) and `TestConfig`
  allows tests to tweak the behavior.
- writer: API for modifying the tables while maintaining cross-table references
- reconciler: Reconciliation from frontends to BPF maps
- maps: "LBMaps" wrapper around BPF maps
- reflectors: Reflects Kubernetes Service, Pod and EndpointSlices to the tables (via Writer)

## Inspecting state

State of load-balancing can be inspected via `cilium-dbg shell`:

```
  $ kubectl exec -it -n kube-system ds/cilium -- cilium-dbg shell
  ...
  > db/show frontends
  > db/show backends
  > db/show services
  > lb/maps-dump
```

You can also explore this in the standalone "repl". See `repl/main.go`.

## Testing

The new architecture makes it easier to write integration tests due to the decoupling. An
integration test for a data source can depend just on the tables & writer and verify that the
tables are correctly populated without having to mock other features or the BPF operations.

An "end-to-end" style test can be found in `tests/script_test.go` that tests going from Kubernetes
objects specified in YAML to the BPF map contents using script tests in `testdata`. This is
the main way of testing the control-plane.

Similar tests can be found from components building on top of load-balancing in `redirectpolicy/script_test.go`
and `pkg/ciliumenvoyconfig/script_test.go`. For more info on script tests see
https://docs.cilium.io/en/latest/contributing/development/hive/#testing-with-hive-script and
https://docs.cilium.io/en/latest/contributing/development/statedb/#script-commands.

For quick feedback loop you can use the `watch.sh` script (in tests/) to run a script test when the
txtar file changes.

IMPORTANT: When adding new test cases it's important to stress test to make sure the new
test is not flaky. Run `stress.sh` to run 500 iterations of all tests.

Tests can be executed normally with "go test":
```
  $ go test ./...
```

To run the privileged tests that use the real BPF maps:
```
  $ cd tests
  $ go test -c
  $ PRIVILEGED_TESTS=1 sudo -E ./tests.test -test.run . -test.v -test.count 1
```

## Benchmarking

The `benchmark/` directory contains a benchmark testing the throughput and memory usage
when going from Kubernetes objects to BPF map contents. Run with `go run ./benchmark/cmd`.
Highly encouraged to use this when doing structural changes or adding additional indexing.

The average result that you can expect is around ~50k  per second with ~50 objects allocated
per service.
