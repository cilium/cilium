For CoreDNS: Enable reverse lookups
===================================

In order for the TLS certificates between etcd peers to work correctly, a DNS
reverse lookup on a pod IP must map back to pod name. If you are using CoreDNS,
check the CoreDNS ConfigMap and validate that ``in-addr.arpa`` and ``ip6.arpa``
are listed as wildcards for the kubernetes block like this:

::

    kubectl -n kube-system edit cm coredns
    [...]
    apiVersion: v1
    data:
      Corefile: |
        .:53 {
            errors
            health
            kubernetes cluster.local in-addr.arpa ip6.arpa {
              pods insecure
              upstream
              fallthrough in-addr.arpa ip6.arpa
            }
            prometheus :9153
            proxy . /etc/resolv.conf
            cache 30
        }

The contents can look different than the above. The specific configuration that
matters is to make sure that ``in-addr.arpa`` and ``ip6.arpa`` are listed as
wildcards next to ``cluster.local``.

You can validate this by looking up a pod IP with the ``host`` utility from any
pod:

::

    host 10.60.20.86
    86.20.60.10.in-addr.arpa domain name pointer cilium-etcd-972nprv9dp.cilium-etcd.kube-system.svc.cluster.local.


Deploy Cilium + cilium-etcd-operator
====================================

The following all-in-one YAML will deploy all required components to bring up
Cilium including an etcd cluster managed by the cilium-etcd-operator.

.. note::

   It is important to always deploy Cilium and the cilium-etcd-operator
   together. The cilium-etcd-operator is not able to bootstrap without running
   Cilium instances. It requires a CNI plugin to provide networking between the
   etcd pods forming the cluster. Cilium has special logic built in that allows
   etcd pods to communicate during the bootstrapping phase of Cilium.

For Docker as container runtime:
--------------------------------

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium.yaml

For CRI-O as container runtime:
-------------------------------

.. tabs::
  .. group-tab:: K8s 1.13

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.13/cilium-crio.yaml

  .. group-tab:: K8s 1.12

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.12/cilium-crio.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-crio.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-crio.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-crio.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-crio.yaml
