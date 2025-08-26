.. Note::

    Note that these Envoy resources are not validated by K8s at all, so
    any errors in the Envoy resources will only be seen by the Cilium
    Agent observing these CRDs. This means that ``kubectl apply`` will
    report success, while parsing and/or installing the resources for the
    node-local Envoy instance may have failed. Currently the only way of
    verifying this is by observing Cilium Agent logs for errors and
    warnings. Additionally, Cilium Agent will print warning logs for any
    conflicting Envoy resources in the cluster.

.. Note::

    Note that Cilium Ingress Controller will configure required Envoy
    resource under the hood. Please check Cilium Agent logs if you are
    creating Envoy resources explicitly to make sure there is no conflict.
