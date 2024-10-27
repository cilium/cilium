Known Issues
############

* If your Cilium install's nodes have multiple network devices, Ingress
  traffic can have issues with traffic to Envoy arriving on the same node as a
  backend Pod unless you set ``endpointRoutes.enabled`` to ``true`` in Helm.
  Fixing this issue is tracked in `#24318 <https://github.com/cilium/cilium/issues/24318>`_.

