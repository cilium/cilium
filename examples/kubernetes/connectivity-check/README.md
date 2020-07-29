# Connectivity Check

Set of deployments that will perform a series of connectivity checks via
liveness and readiness checks. An unhealthy/unready pod indicates a problem.

## Connectivity checks

* [Standard connectivity checks](./connectivity-check.yaml)
* [Standard connectivity checks with hostport](./connectivity-check-hostport.yaml)
  * Requires either eBPF hostport to be enabled or portmap CNI chaining.
* [Single-node connectivity checks](./connectivity-check-single-node.yaml)
  * Standard connectivity checks minus the checks that require multiple nodes.
* [Proxy connectivity checks](./connectivity-check-proxy.yaml)
  * Extra checks for various paths involving Layer 7 policy.

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
  definitons used above. For more information, run `make help` in this
  directory.

For more information, see https://github.com/cilium/cilium/pull/12599 .
