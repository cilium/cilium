# Connectivity Check

Set of deployments that will perform a series of connectivity checks via
liveness and readiness checks. An unhealthy/unready pod indicates a problem.

## Connectivity checks

* [Standard connectivity checks](./connectivity-check.yaml)
* [Standard connectivity checks (internal traffic only)](./connectivity-check-internal.yaml)
  * Same as standard connectivity checks but without external traffic check (e.g 1.1.1.1 and www.google.com).
  * This file is currently used in github action conformance test with kind IPv6 cluster.
* [Standard connectivity checks with hostport](./connectivity-check-hostport.yaml)
  * Requires either eBPF hostport to be enabled or portmap CNI chaining.
* [Single-node connectivity checks](./connectivity-check-single-node.yaml)
  * Standard connectivity checks minus the checks that require multiple nodes.
* [Proxy connectivity checks](./connectivity-check-proxy.yaml)
  * Extra checks for various paths involving Layer 7 policy.
* [Connectivity checks with only k8s netpol](./connectivity-check-netpol-only.yaml)
  * Similar to the standard connectivity checks but without using any Cilium CRDs for network policy.

## Developer documentation

These checks are written in [CUE](https://cuelang.org/) to define various
checks in a concise manner. The definitions for the checks are split across
multiple files per the following logic:

* `resources.cue`: The main definitions for templating all Kubernetes resources
  including Deployment, Service, and CiliumNetworkPolicy.
* `echo-servers.cue`: Data definitions for all `echo-*` servers used for other
  connectivity checks.
* `defaults.cue`: Default parameters used to define how specific checks connect
  to particular echo servers, including selecting the probe destination,
  selecting pod affinity, and default image for all checks.
* `network.cue`, `policy.cue`, `proxy.cue`, `services.cue`: Data definitions
  for various connectivity checks at different layers and using different
  features. L7 policy checks are defined in `proxy.cue` and not `policy.cue`.
* `*_tool.cue`: Various CLI tools for listing and generating the YAML
  definitions used above. For more information, run `make help` in this
  directory.

For more information, see https://github.com/cilium/cilium/pull/12599 .

## Listing and generating connectivity checks

```
$ make help
List connectivity-check resources specified in this directory

Usage:
  cue [-t component=<component>] [-t kind=<kind>] [-t name=<name>] [-t quarantine=true] [-t topology=<topology>] [-t traffic=any] [-t type=<tooltype>] <command>

Available Commands:
  dump   Generate connectivity-check YAMLs from the cuelang scripts
  ls     List connectivity-check resources specified in this directory

Available filters:
  component   { all | default | network | policy | services | hostport | proxy } (default excludes hostport, proxy)
  kind        { Deployment | Service | CiliumNetworkPolicy } (default: all)
  quarantine  { true | false } (default: false)
  topology    { any | single-node } (default: any)
  traffic     { any | internal | external } (default: any)
  type        { autocheck | tool } (default: autocheck)

Example command:
$ cue -t component=all ls

The cue CLI may be installed via the following command:
$ go get cuelang.org/go@v0.2.2
```
