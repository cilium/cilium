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

A health checker observes the backends table to find targets to health check and uses
`Writer.SetBackendHealth` to update the state.

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
  $ cilium-dbg statedb experimental frontends
  $ cilium-dbg statedb experimental backends
  $ cilium-dbg statedb experimental services
  $ cilium-dbg statedb health | grep experimental
```
## Integration testing

The new architecture makes it easier to write integration tests due to the decoupling. An
integration test for a data source can depend just on the tables & writer and verify that the
tables are correctly populated without having to mock other features or the BPF operations. An
example of this sort of test is in `writer_test.go`.

A more "end-to-end" style test can be found in `k8s_test.go` that tests going from Kubernetes
objects specified in YAML to the BPF map contents.

To run the privileged tests:
```
  $ go test -c
  $ PRIVILEGED_TESTS=1 sudo -E ./experimental.test -test.run . -test.v -test.count 1
```
## Unimplemented features

This section lists the major unimplemented features and some thoughts on how we'd go about
implementing them.

### Local Redirect Policies

These are currently implemented by `pkg/redirectpolicy`. The manager there subscribes to pods
and redirect policies and create a `-local` service with the backends derived from the matched
local pods.

With the new architecture this should be implemented as a controller that watches `Table[Pod]`
and `Table[CiliumLocalRedirectPolicy]` and updates the load-balancing state accordingly when
they change.  The controller should be as stateless as possible.

Still TBD is the design for how services would be overridden to redirect traffic to a local pod.
The essential problem is that there's two sets of backends for the service: the normal backends
and the LRP backends, and it should be possible to return to normal when the LRP is removed.
One option is to use a generated service name for the set of LRP backends and then set this in
the Service object.  The matching of frontends with backends would then see if this field is
set and use the alternative service name. The challenge here is how to make it easy for observers
of the tables, e.g. how the L7 proxy would be able to correctly look up backends for a specific
service.

### L7 proxy

A CiliumEnvoyConfig CRD specifies that traffic for a specific service should be redirected to
an Envoy instance. This is accomplished by setting the L7 proxy port in the services BPF map
value. The current implementation lives in `pkg/ciliumenvoyconfig` and on `Resource[CiliumEnvoyConfig]`
event calls to ServiceManager to add the L7 proxy port to matching services.

As with LRPs it should be possible to reimplement this in mostly stateless way by switching
`Resource[CiliumEnvoyConfig]` to `Table[CiliumEnvoyConfig]` and having the controller watch
`Table[Service]` for matches and updating when the service matches with a CiliumEnvoyConfig. To avoid
the intermediate state where a service is missing the L7 proxy port we can implement a "service
hook" that is invoked when a service is upserted to do a query against `Table[CiliumEnvoyConfig]`
and fill it in on the fly.

### REST API (/service)

The REST API handlers are currently implemented against ServiceManager. Implementing the inspection
of the state is relatively easy thanks to the generic StateDB HTTP API. Handlers for modifying the
state (e.g. for lb-only use) are trickier due to the semantic differences. In the new design the
"primary key" is the `L3n4Addr` rather than the `ID`, so changes would be needed to the REST API to
accomodate this. There's relatively few users of this and the message has been that the change from
IDs to addresses would simplify their lives.

Additional question here is the change to the restoration of data from BPF maps. The new implementation
only restores the IDs (in order to reuse them and avoid connection disruption), but not all the rest of
the data. This means that in lb-only use the services and backends need to be restored when the agent has
restarted. Likely it would make sense to rethink the API to allow implementation of "data sources" via
the REST API that can be resynced, e.g. move into a more of a pull-style API.

### ClusterMesh

ClusterMesh is implemented by merging the external services and endpoints in ServiceCache
(`Merge*` methods). This can be now implemented more directly with the `Writer` API. The 
ClusterMesh services and backends are essentially the same as those coming from Kubernetes
and do not require any special handling.

One notable requirement for ClusterMesh is the need to prune non-global services before
ClusterMesh-sourced services are initialized. See `cf4279c68202bae83917b65b8e7da21e20869def`
for context. Yet unclear how to cleanly implement this. The reconciler currently won't
perform the `Prune()` operation if there are any pending initializers.

### ServiceCache replacement

ServiceCache in addition to merging Services with Endpoints and forwarding as events to a
handler, it has a set of getters and a `Notifications()` stream (used by policy engine).

These are all easy to replace by queries against the service/frontend/backend tables.

### kvstore data source

### Misc features

- ServiceAffinity/"Preferred"
- TopologyAware/Zones
- LoopbackHostPort
