.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _code_overview:

Code Overview
=============

This section provides an overview of the Cilium & Hubble source code directory
structure. It is useful to get an initial overview on where to find what.

High-level
----------

Top-level directories `github.com/cilium/cilium <https://github.com/cilium/cilium>`_:

api
  The Cilium & Hubble API definition.

bpf
  The eBPF datapath code

bugtool
  CLI for collecting agent & system information for bug reporting

cilium
  Cilium CLI client

contrib, tools
  Additional tooling and resources used for development

daemon
  The cilium-agent running on each node

examples
  Various example resources and manifests. Typically require to be modified
  before usage is possible.

hubble-relay
  Hubble Relay server

install
  Helm deployment manifests for all components

pkg
  Common Go packages shared between all components

operator
  Operator responsible for centralized tasks which do not require to be
  performed on each node.

plugins
  Plugins to integrate with Kubernetes and Docker

test
  End-to-end integration tests run in the :ref:`testsuite`.

Cilium
------

api/v1/openapi.yaml
  API specification of the Cilium API. Used for code generation.

api/v1/models/
  Go code generated from openapi.yaml representing all API resources

bpf
  The eBPF datapath code

cilium
  Cilium CLI client

cilium-health
  Cilium cluster connectivity CLI client

daemon
  cilium-agent specific code

plugins/cilium-cni
  The CNI plugin to integrate with Kubernetes

plugins/cilium-docker
  The Docker integration plugin

Hubble
------

The server-side code of Hubble is integrated into the Cilium repository. The
Hubble CLI can be found in the separate repository `github.com/cilium/hubble
<https://github.com/cilium/hubble>`_. The Hubble UI can be found in the
separate repository `github.com/cilium/hubble-ui
<https://github.com/cilium/hubble-ui>`_.

api/v1/external, api/v1/flow, api/v1/observer, api/v1/peer, api/v1/relay
  API specifications of the Hubble APIs.

hubble-relay
  Hubble Relay agent

pkg/hubble
  All Hubble specific code

pkg/hubble/container
  Ring buffer implementation

pkg/hubble/filters
  Flow filtering capabilities

pkg/hubble/metrics
  Metrics plugins providing Prometheus based on Hubble's visibility

pkg/hubble/observe
  Layer running on top of the Cilium datapath monitoring, feeding the metrics
  and ring buffer.

pkg/hubble/parser
  Network flow parsers

pkg/hubble/peer
  Peer service implementation

pkg/hubble/relay
  Hubble Relay service implementation

pkg/hubble/server
  The server providing the API for the Hubble client and UI

Important common packages
-------------------------

pkg/allocator
  Security identity allocation

pkg/bpf
  Abstraction layer to interact with the eBPF runtime

pkg/client
  Go client to access Cilium API

pkg/clustermesh
  Multi-cluster implementation including control plane and global services

pkg/controller
  Base controller implementation for any background operation that requires
  retries or interval-based invocation.

pkg/datapath
  Abstraction layer for datapath interaction

pkg/defaults
  All default values

pkg/elf
  ELF abstraction library for the eBPF loader

pkg/endpoint
  Abstraction of a Cilium endpoint, representing all workloads.

pkg/endpointmanager
  Manager of all endpoints

pkg/envoy
  Envoy proxy interactions

pkg/fqdn
  FQDN proxy and FQDN policy implementation

pkg/health
  Network connectivity health checking

pkg/hive
  A dependency injection framework for modular composition of applications

pkg/identity
  Representation of a security identity for workloads

pkg/ipam
  IP address management

pkg/ipcache
  Global cache mapping IPs to endpoints and security identities

pkg/k8s
  All interactions with Kubernetes

pkg/kafka
  Kafka protocol proxy and policy implementation

pkg/kvstore
  Key-value store abstraction layer with backends for etcd

pkg/labels
  Base metadata type to describe all label/metadata requirements for workload
  identity specification and policy matching.

pkg/loadbalancer
  Control plane for load-balancing functionality

pkg/maps
  eBPF map representations

pkg/metrics
  Prometheus metrics implementation

pkg/monitor
  eBPF datapath monitoring abstraction

pkg/node
  Representation of a network node

pkg/option
  All available configuration options

pkg/policy
  Policy enforcement specification & implementation

pkg/proxy
  Layer 7 proxy abstraction

pkg/service
  Representation of a load-balancing service

pkg/trigger
  Implementation of trigger functionality to implement event-driven
  functionality
