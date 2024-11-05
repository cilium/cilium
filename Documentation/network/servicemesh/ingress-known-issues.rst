Known Issues
############

* If your Cilium install's nodes have multiple network devices, Ingress
  traffic can have issues with traffic to Envoy arriving on the same node as a
  backend Pod unless you set ``endpointRoutes.enabled`` to ``true`` in Helm.
  Fixing this issue is tracked in `#24318 <https://github.com/cilium/cilium/issues/24318>`_.
* Similarly, you are using Native Routing, (no tunneling) and your Cilium install
  sets the Helm ``bpf.masquerade`` value to ``true``,you can also have issues
  with same-node backend routing. The workaround in this case is to set
  ``hostLegacyRouting`` to ``true``. Fixing this issue is tracked in
  `#31653 <https://github.com/cilium/cilium/issues/31653>`_.
