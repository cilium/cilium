# Connectivity Check

Set of deployments that will perform a series of connectivity checks via
liveness and readiness checks. An unhealthy/unready pod indicates a problem.

## Note: HostPort test

Cilium does not enable HostPort by default. Therefore you will have the
following two pods remain unready unless you enable HostPort via chaining:

    pod-to-b-intra-node-hostport-6549fc5b88-ngcl5           0/1     Running   3          3m31s
    pod-to-b-multi-node-hostport-795964f8c8-79bxp           0/1     Running   3          3m31s
