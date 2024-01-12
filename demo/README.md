This is a demo for StateDB and generic reconcilers.

It's a (bogus) simulation of how one could write part of Cilium's
load-balancing control-plane using StateDB and the generic reconcilers.

The application pulls Service and Endpoints objects from Kubernetes
and from those fills in the "frontends" and "backends" BPF maps.
Additionally it has a HTTP API for creating services and endpoints (the
internal objects).

The application is built using:

* pkg/hive for wiring up the different modules together
* pkg/hive/job for managing background jobs
* pkg/k8s/client for accessing Kubernetes
* pkg/statedb for managing and consuming state
* pkg/statedb/reflector for reflecting k8s to statedb
* pkg/statedb/reconciler for reconciling changes to state

The application is split into two layers:

* Control-plane which integrates with the outside world (k8s, HTTP)
  and transforms the "outside intent" to desired datapath state.

* Datapath which applies the desired state to the kernel BPF state.
  It exports APIs to manipulate the desired state towards the control-plane
  layer.

This split keeps the complex high-level logic in an easily testable
platform-indepentent control-plane layer, and keeps the business logic
out of the lower datapath layer.

It aims to showcase:

1) Building an extendable control-plane with StateDB to which new data sources
   can be added (controlplane/k8s.go, controlplane/handlers.go).

2) Writing a controller that computes desired state when inputs change
   (controlplane/controllers.go). Showing how to integration-test such
   a controller (controlplane/controllers_test.go) with real data. 

3) Writing a datapath that uses StateDB for desired state, with a safe API
   for modifying the desired state.
   (datapath/models.go, datapath/{frontends,backends}.go).

4) Showing how to use the generic reconciler to reconcile BPF maps and how
   to inspect the reconciliation state.
   (datapath/bpf_ops.go, datapath/{frontends,backends}.go).

To build and run the application:

    $ make run

(this will run as root via sudo and needs ~/.kube/config)

To run tests:

    $ make test

Things to try
-------------

Create a new pod with a service that exposes it:

    $ kubectl run -it --rm nginx --image=nginx --expose --port 12345
    $ make statedb
    # try to find nginx related desired state

Use the HTTP API to add or delete a service and its endpoints:

    $ make add
    $ make statedb
    $ make delete
    $ make statedb
 
Inspect the contents of StateDB:

    $ make statedb

Inspect the module health of the demo application:

    $ make health

Inspect metrics related to reconciliation:

    $ make metrics | grep cilium_reconciler

Inspect the BPF maps managed by this demo:

    $ make maps

Inspect the Hive dependencies:

    $ make hive
