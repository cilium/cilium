.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_etcd_operator:

******************************
Installation with managed etcd
******************************

The standard :ref:`k8s_quick_install` guide will set up Cilium to use
Kubernetes CRDs to store and propagate state between agents. Use of CRDs can
impose scale limitations depending on the size of your environment. Use of etcd
optimizes the propagation of state between agents. This guide explains the
steps required to set up Cilium with a managed etcd where etcd is managed by an
operator which maintains an etcd cluster as part of the Kubernetes cluster.

The identity allocation remains to be CRD-based which means that etcd remains
an optional component to improve scalability. Failures in providing etcd will
not be critical to the availability of Cilium but will reduce the efficacy of
state propagation. This allows the managed etcd to recover while depending on
Cilium itself to provide connectivity and security.

Should you encounter any issues during the installation, please refer to the
:ref:`troubleshooting_k8s` section and / or seek help on the `Slack channel`.

.. include:: requirements_intro.rst

Deploy Cilium + cilium-etcd-operator
====================================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set etcd.enabled=true \\
      --set etcd.managed=true


Validate the Installation
=========================

You can monitor as Cilium and all required components are being installed:

.. parsed-literal::

    kubectl -n kube-system get pods --watch
    NAME                                    READY   STATUS              RESTARTS   AGE
    cilium-etcd-operator-6ffbd46df9-pn6cf   1/1     Running             0          7s
    cilium-operator-cb4578bc5-q52qk         0/1     Pending             0          8s
    cilium-s8w5m                            0/1     PodInitializing     0          7s
    coredns-86c58d9df4-4g7dd                0/1     ContainerCreating   0          8m57s
    coredns-86c58d9df4-4l6b2                0/1     ContainerCreating   0          8m57s

It may take a couple of minutes for the etcd-operator to bring up the necessary
number of etcd pods to achieve quorum. Once it reaches quorum, all components
should be healthy and ready:

.. parsed-literal::

    cilium-etcd-8d95ggpjmw                  1/1     Running   0          78s
    cilium-etcd-operator-6ffbd46df9-pn6cf   1/1     Running   0          4m12s
    cilium-etcd-t695lgxf4x                  1/1     Running   0          118s
    cilium-etcd-zw285m6t9g                  1/1     Running   0          2m41s
    cilium-operator-cb4578bc5-q52qk         1/1     Running   0          4m13s
    cilium-s8w5m                            1/1     Running   0          4m12s
    coredns-86c58d9df4-4g7dd                1/1     Running   0          13m
    coredns-86c58d9df4-4l6b2                1/1     Running   0          13m
    etcd-operator-5cf67779fd-hd9j7          1/1     Running   0          2m42s

.. include:: namespace-kube-system.rst
.. include:: hubble-enable.rst

Troubleshooting
===============

 * Make sure that ``kube-dns`` or ``coredns`` is running and healthy in the
   ``kube-system`` namespace. A functioning Kubernetes DNS is strictly required
   in order for Cilium to resolve the ClusterIP of the etcd cluster. If either
   ``kube-dns`` or ``coredns`` were already running before Cilium was deployed,
   the pods may be managed by a former CNI plugin. ``cilium-operator`` will
   automatically restart the pods to ensure that they are being managed by the
   Cilium CNI plugin. You can manually restart the pods as well if required and
   validate that Cilium is managing ``kube-dns`` or ``coredns`` by running:

   .. code:: bash

        kubectl -n kube-system get cep

   You should see ``kube-dns-xxx`` or ``coredns-xxx`` pods.

 * In order for the entire system to come up, the following components have to
   be running at the same time:

   * ``kube-dns`` or ``coredns``
   * ``cilium-xxx``
   * ``cilium-operator-xxx``
   * ``cilium-etcd-operator``
   * ``etcd-operator``
   * ``cilium-etcd-xxx``

   All timeouts are configured that this will typically work out smoothly even
   if some of the pods restart once or twice. In case any of the above pods get
   into a long ``CrashLoopBackoff``, bootstrapping can be expedited  by
   restarting the pods to reset the ``CrashLoopBackoff`` time.

CoreDNS: Enable reverse lookups
-------------------------------

In order for the TLS certificates between etcd peers to work correctly, a DNS
reverse lookup on a pod IP must map back to pod name. If you are using CoreDNS,
check the CoreDNS ConfigMap and validate that ``in-addr.arpa`` and ``ip6.arpa``
are listed as wildcards for the kubernetes block like this:

    .. tabs::
        .. group-tab:: Kubernetes 1.16+

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
                        forward . /etc/resolv.conf
                        cache 30
                    }

        .. group-tab:: Kubernetes < 1.16

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

.. _k8s_what_is_the_cilium_etcd_operator:

What is the cilium-etcd-operator?
=================================

The cilium-etcd-operator uses and extends the etcd-operator to guarantee quorum,
auto-create certificates, and manage compaction:

 * Automatic re-creation of the etcd cluster when the cluster loses quorum. The
   standard etcd-operator will refuse to bring up new etcd nodes and the etcd
   cluster becomes unusable.

 * Automatic creation of certificates and keys. This simplifies the
   installation of the operator and makes the certificates and keys required to
   access the etcd cluster available to Cilium using a well known Kubernetes
   secret name.

 * Compaction is automatically handled.

.. _k8s_etcd_operator_limitations:

Limitations
===========

Use of the cilium-etcd-operator offers a lot of advantages including simplicity
of installation, automatic management of the etcd cluster including compaction,
restart on quorum loss, and automatic use of TLS. There are several
disadvantages which can become of relevance as you scale up your clusters:

* etcd nodes operated by the etcd-operator will not use persistent storage.
  Once the etcd cluster looses quorum, the etcd cluster is automatically
  re-created by the cilium-etcd-operator. Cilium will automatically recover and
  re-create all state in etcd. This operation can take couple of seconds
  and may cause minor disruptions as ongoing distributed locks are invalidated
  and security identities have to be re-allocated.

* etcd is very sensitive to disk IO latency and requires fast disk access at a
  certain scale. The cilium-etcd-operator will not take any measures to provide
  fast disk access and performance will depend whatever is provided to the pods
  in your Kubernetes cluster. See `etcd Hardware recommendations
  <https://etcd.io/docs/latest/op-guide/hardware/>`_ for more details.
