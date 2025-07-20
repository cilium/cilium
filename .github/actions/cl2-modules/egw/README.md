# Egress Gateway Scale and Performance Testing

This directory contains utilities for performing scale and performance tests on
Cilium's Egress Gateway feature.

An additional docker image is utilized to perform the test, which can be found
within the [cilium/scaffolding](https://github.com/cilium/scaffolding/tree/main/egw-scale-utils)
repository. Refer to the README file therein available for additional information
on the `egw-scale-utils` tool.

## Environment Details

The cluster needs to be created with four types of nodes:

1. At least one Node for the EGW clients to be deployed onto, labeled with
   `role.scaffolding/egw-client: true`.
2. At least one node to act as the EGW Node, labeled with
   `role.scaffolding/egw-node: true`.
3. A node to deploy the external target onto, labeled with
   `cilium.io/no-schedule "true"`. This label will prevent Cilium from being
   scheduled onto the node, tricking Cilium Agents running on other nodes into
   believing the node is external to the cluster.
4. A node to deploy monitoring infrastructure onto, to isolate
   monitoring-related traffic and resource usage from the test, labeled
   with `role.scaffolding/monitoring: true`.

## Tests Overview

The remainder of this README provides an overview of the test suite. The test
suite can be run in *baseline* mode (i.e., without deploying the egress gateway
policies), to measure baseline performance, or in *egw* mode, to measure
egress gateway performance. This is controlled via the `CL2_EGW_CREATE_POLICY`
environment variable.

The full list of configurations is provided at the top of the
[config.yaml](config.yaml) file.

### Pod Masquerade Delay

This test measures the amount of time it takes for a newly started pod to be able
to contact an external destination via the egress gateway. Additionally, it assesses
the scalability of the egress gateway control plane.

At a high level, the test leverages the `egw-scale-utils` utility, and is organized
as follows:

* The appropriate egress gateway policy is applied to the cluster (in *egw* mode).
* A server representing the external destination is deployed on the dedicated node;
  in *egw* mode, it is configured to reply to clients only if the request comes
  from the expected egress gateway IP.
* *N* clients are deployed into the cluster (at a rate of *Q* per second); each
  client tries to contact the server, and measures how much it takes before it
  receives a response from the server (that is, the packets correctly flow through
  the egress gateway); this is referred to as the *low-scale* test.
* The scale is artificially increased via the creation of synthetic CiliumEndpoints,
  synthetic nodes, and extra EGW policies (each matching all synthetic endpoints
  and a subset of the synthetic nodes).
* *N* new clients are deployed into the cluster (at a rate of *Q* per second),
  measuring again the masquerade delay; this is referred to as the *high-scale* test.
* CPU and memory used by Cilium agents during the whole test is measured.

### Network Performance Testing

This test characterizes the main egress gateway performance metrics, in terms of
throughput, transaction rate and latency. This validates the potential overhead
introduced by traffic redirection to the egress gateway node. Additionally, it
measures the amount of CPU consumed by the egress gateway node.

At a high level, the test leverages the `cilium connectivity perf` suite (based
on `netperf`  under the hood), and is organized as follows:

* A `netperf` server pod representing the external destination is deployed on
  the dedicated node.
* A `netperf` client pod is deployed on one of the client nodes; the client is
  matched by an egress gateway policy as appropriate.
* The full suite of netperf tests (including TCP/UDP STREAM, TCP/UDP RR, TCP CRR) is
  run to evaluate the different performance metrics; each test is run for 30 seconds.
* CPU and memory consumed by the different nodes during the whole test is measured.

### Max Parallel Connections

This test assesses the maximum number of connections that can be opened towards an
external target via the egress gateway, and the associated latency. Additionally,
it measures the amount of CPU consumed by Cilium agents during the process.

At a high level, the test leverages the `egw-scale-utils` utility, with the external
target configured to keep client connections open, and the clients continuously
opening new connections until repeated failures are encountered. The test is
repeated four times sequentially, to assess the following combinations:

* *base*: client hosted on a given node *N1*, towards the target listening on
  port *P1*;
* *same-port-node*: client hosted on the same node *N1*, towards the same target
  listening on port *P1*; it evaluates whether a client hosted on the same node,
  and targeting the same destination is affected by the other connections.
* *diff-node*: client hosted on a different node *N2*, towards the same target
  listening on port *P1*; it evaluates whether a client hosted on a different
  node, and targeting the same destination is affected by the other connections.
* *diff-port*: client hosted on the same node *N1*, towards a different target
  listening on port *P2*; it evaluates whether a client hosted on the same node,
  but targeting a different destination is affected by the other connections.
