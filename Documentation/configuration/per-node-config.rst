.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _per-node-configuration:

**********************
Per-node configuration
**********************

.. include:: ../beta.rst

The Cilium agent process (a.k.a. DaemonSet) supports setting configuration
on a per-node basis. This allows overriding :ref:`cilium-config-configmap`
for a node or set of nodes. It is managed by CiliumNodeConfig objects.

This feature is useful for:

- Gradually rolling out changes.
- Selectively enabling features that require specific hardware:

    * :ref:`XDP acceleration`
    * :ref:`ipv6_big_tcp`

CiliumNodeConfig objects
------------------------

A CiliumNodeConfig object allows for overriding ConfigMap / Agent arguments.
It consists of a set of fields and a label selector. The label selector
defines to which nodes the configuration applies. As is the standard with
Kubernetes, an empty LabelSelector (e.g. ``{}``) selects all nodes.

.. note::
    Creating or modifying a CiliumNodeConfig will not cause changes to take effect
    until pods are deleted and re-created (or their node is restarted).


Example: selective XDP enablement
---------------------------------

To enable :ref:`XDP acceleration` only on nodes with necessary
hardware, one would label the relevant nodes and override their configuration.

.. code-block:: yaml

    apiVersion: cilium.io/v2alpha1
    kind: CiliumNodeConfig
    metadata:
      namespace: kube-system
      name: enable-xdp
    spec:
      nodeSelector:
        matchLabels:
          io.cilium.xdp-offload: "true"
      defaults:
        bpf-lb-acceleration: native

Example: KubeProxyReplacement Rollout
-------------------------------------

To roll out :ref:`kube-proxy replacement <kubeproxy-free>` in a gradual manner,
you may also wish to use the CiliumNodeConfig feature. This will label all migrated
nodes with ``io.cilium.migration/kube-proxy-replacement: strict``

.. warning::

    You must have installed Cilium with the Helm values ``k8sServiceHost`` and
    ``k8sServicePort``. Otherwise Cilium will not be able to reach the Kubernetes
    APIServer after kube-proxy is uninstalled.

    You can apply these two values to a running cluster via ``helm upgrade``.

#. Patch kube-proxy to only run on unmigrated nodes.

    .. code-block:: shell-session

        kubectl -n kube-system patch daemonset kube-proxy --patch '{"spec": {"template": {"spec": {"affinity": {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [{"key": "io.cilium.migration/kube-proxy-replacement", "operator": "NotIn", "values": ["strict"]}]}]}}}}}}}'

#. Configure Cilium to use strict kube-proxy on migrated nodes

    .. code-block:: shell-session

        cat <<EOF | kubectl apply --server-side -f -
        apiVersion: cilium.io/v2alpha1
        kind: CiliumNodeConfig
        metadata:
          namespace: kube-system
          name: kube-proxy-replacement-strict
        spec:
          nodeSelector:
            matchLabels:
              io.cilium.migration/kube-proxy-replacement: strict
          defaults:
            kube-proxy-replacement: strict
            kube-proxy-replacement-healthz-bind-address: "0.0.0.0:10256"

        EOF

#. Select a node to migrate. Optionally, cordon and drain that node:

    .. code-block:: shell-session

        export NODE=kind-worker
        kubectl label node $NODE --overwrite 'io.cilium.migration/kube-proxy-replacement=strict'
        kubectl cordon $NODE

#. Delete Cilium DaemonSet to reload configuration:

    .. code-block:: shell-session

        kubectl -n kube-system delete pod -l k8s-app=cilium --field-selector spec.nodeName=$NODE

#. Ensure Cilium has the correct configuration:

    .. code-block:: shell-session

        kubectl -n kube-system exec $(kubectl -n kube-system get pod -l k8s-app=cilium --field-selector spec.nodeName=$NODE -o name) -c cilium-agent -- \
            cilium config get kube-proxy-replacement
        strict

#. Uncordon node

    .. code-block:: shell-session

        kubectl uncordon $NODE

#. Cleanup: set default to kube-proxy-replacement:

    .. code-block:: shell-session

        cilium config set --restart=false kube-proxy-replacement strict
        cilium config set --restart=false kube-proxy-replacement-healthz-bind-address "0.0.0.0:10256"
        kubectl -n kube-system delete ciliumnodeconfig kube-proxy-replacement-strict

#. Cleanup: delete kube-proxy daemonset, unlabel nodes

    .. code-block:: shell-session

        kubectl -n kube-system delete daemonset kube-proxy
        kubectl label node --all --overwrite 'io.cilium.migration/kube-proxy-replacement-'
