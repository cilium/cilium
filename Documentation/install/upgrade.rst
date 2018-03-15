.. _admin_upgrade:

*************
Upgrade Guide
*************

Kubernetes Cilium Upgrade
=========================

Cilium should be upgraded using Kubernetes rolling upgrade functionality in order to minimize network disruptions for running workloads.

The safest way to upgrade Cilium to version "\ |SCM_BRANCH|" is by updating the
RBAC rules and the DaemonSet file provided, which makes sure the ConfigMap,
initially set up by ``cilium.yaml``, already stored in the cluster will not be
affected by the upgrade.
Both files are dedicated to "\ |SCM_BRANCH|" for each Kubernetes version.

.. tabs::
  .. group-tab:: K8s 1.7

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.7/rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.7/cilium-ds.yaml

  .. group-tab:: K8s 1.8

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.8/cilium-ds.yaml

  .. group-tab:: K8s 1.9

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.9/cilium-ds.yaml

  .. group-tab:: K8s 1.10

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.10/cilium-ds.yaml

  .. group-tab:: K8s 1.11

    .. parsed-literal::

      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/rbac.yaml
      $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/1.11/cilium-ds.yaml


You can also substitute the desired Cilium version number for vX.Y.Z in the
command below, but be aware that copy of the spec file stored in Kubernetes
might run out-of-sync with the CLI flags, or options, specified by each Cilium
version.

::

    kubectl set image daemonset/cilium -n kube-system cilium-agent=cilium/cilium:vX.Y.Z

To monitor the rollout and confirm it is complete, run: 

::

    kubectl rollout status daemonset/cilium -n kube-system

To undo the rollout via rollback, run:
    
::

    kubectl rollout undo daemonset/cilium -n kube-system

Cilium will continue to forward traffic at L3/L4 during the roll-out, and all endpoints and their configuration will be preserved across
the upgrade rollout.   However, because the L7 proxies implementing HTTP, gRPC, and Kafka-aware filtering currently reside in the 
same Pod as Cilium, they are removed and re-installed as part of the rollout.   As a result, any proxied connections will be lost and 
clients must reconnect.   

