.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

********
Concepts
********

.. _k8s_concepts_deployment:

Deployment
==========

The configuration of a standard Cilium Kubernetes deployment consists of
several Kubernetes resources:

* A ``DaemonSet`` resource:  describes the Cilium pod that is deployed to each
  Kubernetes node.  This pod runs the cilium-agent and associated daemons. The
  configuration of this DaemonSet includes the image tag indicating the exact
  version of the Cilium docker container (e.g., v1.0.0) and command-line
  options passed to the cilium-agent.

* A ``ConfigMap`` resource:  describes common configuration values that are
  passed to the cilium-agent, such as the kvstore endpoint and credentials,
  enabling/disabling debug mode, etc.

* ``ServiceAccount``, ``ClusterRole``, and ``ClusterRoleBindings`` resources:
  the identity and permissions used by cilium-agent to access the Kubernetes
  API server when Kubernetes RBAC is enabled.

* A ``Secret`` resource: describes the credentials used to access the etcd kvstore,
  if required.

Networking For Existing Pods
============================

In case pods were already running before the Cilium :term:`DaemonSet` was deployed,
these pods will still be connected using the previous networking plugin
according to the CNI configuration. A typical example for this is the
``kube-dns`` service which runs in the ``kube-system`` namespace by default.

A simple way to change networking for such existing pods is to rely on the fact
that Kubernetes automatically restarts pods in a Deployment if they are
deleted, so we can simply delete the original kube-dns pod and the replacement
pod started immediately after will have networking managed by Cilium.  In a
production deployment, this step could be performed as a rolling update of
kube-dns pods to avoid downtime of the DNS service.

.. code-block:: shell-session

        $ kubectl --namespace kube-system delete pods -l k8s-app=kube-dns
        pod "kube-dns-268032401-t57r2" deleted

Running ``kubectl get pods`` will show you that Kubernetes started a new set of
``kube-dns`` pods while at the same time terminating the old pods:

.. code-block:: shell-session

        $ kubectl --namespace kube-system get pods
        NAME                          READY     STATUS        RESTARTS   AGE
        cilium-5074s                  1/1       Running       0          58m
        kube-addon-manager-minikube   1/1       Running       0          59m
        kube-dns-268032401-j0vml      3/3       Running       0          9s
        kube-dns-268032401-t57r2      3/3       Terminating   0          57m


Default Ingress Allow from Local Host
=====================================

Kubernetes has functionality to indicate to users the current health of their
applications via `Liveness Probes and Readiness Probes <https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/>`_.
In order for ``kubelet`` to run these health checks for each pod, by default,
Cilium will always allow all ingress traffic from the local host to each pod. 
 
